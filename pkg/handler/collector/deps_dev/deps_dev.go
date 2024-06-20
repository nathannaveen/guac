//
// Copyright 2023 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package deps_dev

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"
	"sync"
	"time"

	pb "deps.dev/api/v3alpha"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/collectsub/datasource"
	"github.com/guacsec/guac/pkg/events"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/guacsec/guac/pkg/metrics"
	"github.com/guacsec/guac/pkg/version"
	jsoniter "github.com/json-iterator/go"
	"golang.org/x/exp/maps"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

const (
	DepsCollector               = "deps.dev"
	goUpperCase                 = "GO"
	golang                      = "golang"
	maven                       = "maven"
	sourceRepo                  = "SOURCE_REPO"
	GetProjectDurationHistogram = "http_deps_dev_project_duration"
	GetVersionErrorsCounter     = "http_deps_dev_version_errors"
	prometheusPrefix            = "deps_dev"
)

type IsDepPackage struct {
	CurrentPackageInput *model.PkgInputSpec
	DepPackageInput     *model.PkgInputSpec
	IsDependency        *model.IsDependencyInputSpec
}

type PackageComponent struct {
	CurrentPackage *model.PkgInputSpec
	Source         *model.SourceInputSpec
	Scorecard      *model.ScorecardInputSpec
	IsDepPackages  []*IsDepPackage
	DepPackages    []*PackageComponent
	UpdateTime     time.Time
}

type depsCollector struct {
	collectDataSource    datasource.CollectSource
	client               pb.InsightsClient
	poll                 bool
	retrieveDependencies bool
	interval             time.Duration
	Metrics              metrics.MetricCollector
	checkedPurls         map[string]*PackageComponent
	ingestedSource       map[string]*model.SourceInputSpec
	projectInfoMap       map[string]*pb.Project
	versions             map[string]*pb.Version
	dependencies         map[string]*pb.Dependencies
}

var registerOnce sync.Once

var depsDevSupportedPkgTypes = map[string]bool{
	"golang": true,
	"cargo":  true,
	"maven":  true,
	"npm":    true,
	"nuget":  true,
}

func NewDepsCollector(ctx context.Context, collectDataSource datasource.CollectSource, poll, retrieveDependencies bool, interval time.Duration) (*depsCollector, error) {
	ctx = metrics.WithMetrics(ctx, prometheusPrefix)
	// Get the system certificates.
	sysPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("failed to get system cert: %w", err)
	}

	// Connect to the service using TLS.
	creds := credentials.NewClientTLSFromCert(sysPool, "")
	conn, err := grpc.Dial("api.deps.dev:443",
		grpc.WithTransportCredentials(creds),
		grpc.WithUserAgent(version.UserAgent))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to api.deps.dev: %w", err)
	}

	// Create a new Insights Client.
	client := pb.NewInsightsClient(conn)

	// Initialize the Metrics collector
	metricsCollector := metrics.FromContext(ctx, prometheusPrefix)
	if err := registerMetricsOnce(ctx, metricsCollector); err != nil {
		return nil, fmt.Errorf("unable to register Metrics: %w", err)
	}
	return &depsCollector{
		collectDataSource:    collectDataSource,
		client:               client,
		poll:                 poll,
		retrieveDependencies: retrieveDependencies,
		interval:             interval,
		checkedPurls:         map[string]*PackageComponent{},
		ingestedSource:       map[string]*model.SourceInputSpec{},
		projectInfoMap:       map[string]*pb.Project{},
		versions:             map[string]*pb.Version{},
		dependencies:         map[string]*pb.Dependencies{},
		Metrics:              metricsCollector,
	}, nil
}

// RetrieveArtifacts get the metadata from deps.dev based on the purl provided
func (d *depsCollector) RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {
	if d.poll {
		for {
			if err := d.populatePurls(ctx, docChannel); err != nil {
				return fmt.Errorf("unable to retrieve purls from collector subscriber: %w", err)
			}
			select {
			// If the context has been canceled it contains an err which we can throw.
			case <-ctx.Done():
				return ctx.Err() // nolint:wrapcheck
			case <-time.After(d.interval):
			}
		}
	} else {
		if err := d.populatePurls(ctx, docChannel); err != nil {
			return fmt.Errorf("unable to retrieve purls from collector subscriber: %w", err)
		}
	}
	return nil
}

func (d *depsCollector) populatePurls(ctx context.Context, docChannel chan<- *processor.Document) error {
	ds, err := d.collectDataSource.GetDataSources(ctx)
	if err != nil {
		return fmt.Errorf("unable to retrieve datasource: %w", err)
	}

	if !d.retrieveDependencies {
		// do validation of and converting purls here, to remove duplicated work in next two calls
		versionKeys, pkgInputs := d.validatePurls(ctx, ds.PurlDataSources)

		d.retrieveVersionsAndProjects(ctx, maps.Values(versionKeys))
		d.collectMetadata(ctx, docChannel, pkgInputs)
		return nil
	}

	err = d.getAllDependencies(ctx, ds.PurlDataSources)
	if err != nil {
		return fmt.Errorf("failed to get all dependencies: %w", err)
	}

	err = d.fetchDependencies(ctx, ds.PurlDataSources, docChannel)
	if err != nil {
		return fmt.Errorf("failed to fetch dependencies: %w", err)
	}
	return nil
}

// returns mappings of purls to VersionKeys and PkgInputSpec, not including the purls that:
// - have already been queried
// - error when converting to PkgInputSpec
// - error when converting to VersionKey
// - don't contain a version
func (d *depsCollector) validatePurls(ctx context.Context, datasources []datasource.Source) (map[string]*pb.VersionKey, map[string]*model.PkgInputSpec) {
	logger := logging.FromContext(ctx)

	validVersionKeys := make(map[string]*pb.VersionKey)
	validPackageInputs := make(map[string]*model.PkgInputSpec)

	for _, ds := range datasources {
		purl := ds.Value

		if _, ok := d.checkedPurls[purl]; ok {
			logger.Infof("purl %s already queried", purl)
			continue
		}

		packageInput, err := helpers.PurlToPkg(purl)
		if err != nil {
			logger.Infof("failed to parse purl to pkg: %s", purl)
			continue
		}

		// if version is not specified, cannot obtain accurate information from deps.dev. Log as info and skip the purl.
		if *packageInput.Version == "" {
			logger.Infof("purl does not contain version, skipping deps.dev query: %s", purl)
			continue
		}

		versionKey, err := getVersionKey(packageInput.Type, packageInput.Namespace, packageInput.Name, packageInput.Version)
		if err != nil {
			logger.Debugf("failed to get VersionKey with the following error: %v", err)
			continue
		}

		validPackageInputs[purl] = packageInput
		validVersionKeys[purl] = versionKey
	}

	return validVersionKeys, validPackageInputs
}

// retrieves version and project information concurrently for all version keys
func (d *depsCollector) retrieveVersionsAndProjects(ctx context.Context, versionKeys []*pb.VersionKey) {
	// channels to signal when the project and version info have been fetched
	projectDone := make(chan bool)
	versionDone := make(chan bool)

	// channels to send the inputs to the goroutines
	projectChan := make(chan *pb.ProjectKey)
	versionChan := make(chan *pb.VersionKey)

	// the projectChan and versionChan are used to send the project key and version key to the respective channels
	go func() {
		// this go routine has to be before the next go routine as it will be pushing into the project channel
		// for each version that is fetched from the version channel it will check if the project has to be fetched
		d.versions = d.getVersions(ctx, versionChan, projectChan) // the results are the stored in the versions map
		versionDone <- true
	}()

	// the project channel is used to send the project key to the project channel
	// these goroutines will be used to fetch the projects concurrently
	go func() {
		// this sets up the goroutine to fetch the projects concurrently for each input
		d.projectInfoMap = d.getProjects(ctx, projectChan) // the results are the stored in the projectInfoMap map
		// posts to the projectDone channel to signal that all projects have been fetched
		projectDone <- true
	}()

	for _, versionKey := range versionKeys {
		versionChan <- versionKey
	}

	close(versionChan)
	<-versionDone
	close(projectChan)
	<-projectDone
}

// For each purl, generate a document containing scorecard and source metadata and write to docChannel.
// For performance, retrieveVersionsAndProjects should be called before to populate d.versions and d.projectInfoMap. Otherwise,
// blocking calls to deps.dev will be made for each purl
func (d *depsCollector) collectMetadata(ctx context.Context, docChannel chan<- *processor.Document, purls map[string]*model.PkgInputSpec) {
	logger := logging.FromContext(ctx)

	var batchRequests []*pb.PurlLookupRequest

	// Collect purls for batch request
	for purl := range purls {
		batchRequests = append(batchRequests, &pb.PurlLookupRequest{Purl: purl})
	}

	// Create batch request
	batchReq := &pb.PurlLookupBatchRequest{
		Requests: batchRequests,
	}

	// Send batch request
	batchResp, err := d.client.PurlLookupBatch(ctx, batchReq)
	if err != nil {
		logger.Infof("failed to lookup purls in batch: %v", err)
	}

	purlToComponents, err := d.collectAdditionalMetadata(ctx, batchResp.Responses)
	if err != nil {
		logger.Debugf("failed to get additional metadata for package, err: %v", err)
	}

	for purl, component := range purlToComponents {
		logger.Infof("obtained additional metadata for package: %s", purl)
		d.checkedPurls[purl] = component

		blob, err := json.Marshal(component)
		if err != nil {
			logger.Errorf("Error marshalling component to json: %s", err)
			continue
		}

		doc := &processor.Document{
			Blob:   blob,
			Type:   processor.DocumentDepsDev,
			Format: processor.FormatJSON,
			SourceInformation: processor.SourceInformation{
				Collector:   DepsCollector,
				Source:      DepsCollector,
				DocumentRef: events.GetDocRef(blob),
			},
		}
		docChannel <- doc
	}
}

// getAllDependencies gets all the dependencies for the purls provided in a concurrent manner.
func (d *depsCollector) getAllDependencies(ctx context.Context, purls []datasource.Source) error {
	// channels to signal when the project and version info have been fetched
	projectDone := make(chan bool)
	versionDone := make(chan bool)

	// channels to send the inputs to the goroutines
	projectChan := make(chan *pb.ProjectKey)
	versionChan := make(chan *pb.VersionKey)
	logger := logging.FromContext(ctx)

	// the projectChan and versionChan are used to send the project key and version key to the respective channels
	go func() {
		// this go routine has to be before the next go routine as it will be pushing into the project channel
		// for each version that is fetched from the version channel it will check if the project has to be fetched
		d.versions = d.getVersions(ctx, versionChan, projectChan) // the results are the stored in the versions map
		versionDone <- true
	}()

	// the project channel is used to send the project key to the project channel
	// these goroutines will be used to fetch the projects concurrently
	go func() {
		// this sets up the goroutine to fetch the projects concurrently for each input
		d.projectInfoMap = d.getProjects(ctx, projectChan) // the results are the stored in the projectInfoMap map
		// posts to the projectDone channel to signal that all projects have been fetched
		projectDone <- true
	}()

	// TODO: Concurrently fetch the dependencies for each purl
	for _, p := range purls {
		purl := p.Value
		packageInput, err := helpers.PurlToPkg(purl)
		if err != nil {
			logger.Infof("failed to parse purl to pkg: %s", purl)
			return nil
		}

		// if version is not specified, cannot obtain accurate information from deps.dev. Log as info and skip the purl.
		if packageInput != nil && *packageInput.Version == "" {
			logger.Debugf("purl does not contain version, skipping deps.dev query: %s", purl)
			return nil
		}

		// Make an RPC Request. The returned result is a stream of
		// DependenciesResponse structs.
		versionKey, err := getVersionKey(packageInput.Type, packageInput.Namespace, packageInput.Name, packageInput.Version)
		if err != nil {
			logger.Debugf("failed to getVersionKey with the following error: %v", err)
			return nil
		}
		// send the version key to the version channel
		versionChan <- versionKey

		dependenciesReq := &pb.GetDependenciesRequest{
			VersionKey: versionKey,
		}

		deps, err := d.client.GetDependencies(ctx, dependenciesReq)
		if err != nil {
			logger.Debugf("failed to get dependencies %v", err)
			return nil
		}
		logger.Infof("Retrieved dependencies for %s", purl)
		d.dependencies[versionKey.String()] = deps

		for i, node := range deps.Nodes {
			// the nodes of the dependency graph. The first node is the root of the graph, which is captured above so skip.
			if i == 0 {
				continue
			}
			pkgtype := ""
			if node.VersionKey.System.String() == goUpperCase {
				pkgtype = golang
			} else {
				pkgtype = strings.ToLower(node.VersionKey.System.String())
			}

			depPurl := "pkg:" + pkgtype + "/" + node.VersionKey.Name + "@" + node.VersionKey.Version
			depPackageInput, err := helpers.PurlToPkg(depPurl)
			if err != nil {
				logger.Debugf("unable to parse purl: %v, error: %v", depPurl, err)
				continue
			}
			depsVersionKey, err := getVersionKey(depPackageInput.Type, depPackageInput.Namespace, depPackageInput.Name, depPackageInput.Version)
			if err != nil {
				logger.Debugf("failed to getVersionKey with the following error: %v", err)
				continue
			}
			versionChan <- depsVersionKey
		}
	}

	close(versionChan)
	<-versionDone
	close(projectChan)
	<-projectDone
	return nil
}

func (d *depsCollector) fetchDependencies(ctx context.Context, purls []datasource.Source, docChannel chan<- *processor.Document) error {
	logger := logging.FromContext(ctx)

	var batchRequests []*pb.PurlLookupRequest

	// Collect purls for batch request
	for _, purl := range purls {
		if _, ok := d.checkedPurls[purl.Value]; ok {
			logger.Infof("purl %s already queried", purl)
			continue
		}

		if len(purl.Value) < 4 {
			logger.Infof("purl values: %v", purl.Value)
		}
		pkgValues := strings.Split(purl.Value[4:], "/") // remove the starting "pkg:"

		if len(pkgValues) == 0 {
			logger.Infof("pkg values: %v", pkgValues)
		}
		pkgType := pkgValues[0]

		if _, ok := depsDevSupportedPkgTypes[pkgType]; ok { // only add if deps dev supports the type of the package
			batchRequests = append(batchRequests, &pb.PurlLookupRequest{Purl: purl.Value})

			//_, err := d.client.PurlLookup(ctx, &pb.PurlLookupRequest{Purl: purl.Value})
			//if err != nil {
			//	logger.Infof("failed to lookup purl %s: %v", purl.Value, err)
			//} else {
			//	logger.Infof("FOUND PURL %s", purl.Value)
			//}
		}
	}

	// Create batch request
	batchReq := &pb.PurlLookupBatchRequest{
		Requests: batchRequests,
	}

	// Send batch request
	batchResp, err := d.client.PurlLookupBatch(ctx, batchReq)
	if err != nil {
		logger.Infof("failed to lookup purls in batch: %v", err)
		//return err
	}

	logger.Infof("batch response: %v", batchResp)

	components, err := d.collectAdditionalMetadata(ctx, batchResp.Responses)
	if err != nil {
		logger.Infof("failed to collect additional metadata: %v", err)
		return err
	}

	for purl, component := range components {
		packageInput, err := helpers.PurlToPkg(purl)
		if err != nil {
			logger.Infof("failed to parse purl to pkg: %s", purl)
			return nil
		}

		// if version is not specified, cannot obtain accurate information from deps.dev. Log as info and skip the purl.
		if *packageInput.Version == "" {
			logger.Infof("purl does not contain version, skipping deps.dev query: %s", purl)
			return nil
		}

		dependencyNodes, deps, err := d.fetchComponentDependencies(ctx, purl)

		// append the i=0 node as the root node of the graph
		dependencyNodes = append([]*PackageComponent{component}, dependencyNodes...)

		component.DepPackages = append(component.DepPackages, dependencyNodes[1:]...)

		for _, edge := range deps.Edges {
			isDep := &model.IsDependencyInputSpec{
				VersionRange:   edge.Requirement,
				DependencyType: model.DependencyTypeDirect,
				Justification:  "dependency data collected via deps.dev",
			}
			foundDepPackage := &IsDepPackage{
				CurrentPackageInput: dependencyNodes[edge.FromNode].CurrentPackage,
				DepPackageInput:     dependencyNodes[edge.ToNode].CurrentPackage,
				IsDependency:        isDep,
			}
			component.IsDepPackages = append(component.IsDepPackages, foundDepPackage)
		}

		logger.Infof("obtained additional metadata for package: %s", purl)

		d.checkedPurls[purl] = component

		blob, err := json.Marshal(component)
		if err != nil {
			return err
		}

		doc := &processor.Document{
			Blob:   blob,
			Type:   processor.DocumentDepsDev,
			Format: processor.FormatJSON,
			SourceInformation: processor.SourceInformation{
				Collector:   DepsCollector,
				Source:      DepsCollector,
				DocumentRef: events.GetDocRef(blob),
			},
		}
		docChannel <- doc
	}

	return nil
}

func (d *depsCollector) fetchComponentDependencies(ctx context.Context, purl string) ([]*PackageComponent, *pb.Dependencies, error) {
	logger := logging.FromContext(ctx)

	packageInput, err := helpers.PurlToPkg(purl)
	if err != nil {
		logger.Infof("failed to parse purl to pkg: %s", purl)
		return nil, nil, fmt.Errorf("failed to parse purl to pkg: %s", purl)
	}

	// if version is not specified, cannot obtain accurate information from deps.dev. Log as info and skip the purl.
	if *packageInput.Version == "" {
		logger.Infof("purl does not contain version, skipping deps.dev query: %s", purl)
		return nil, nil, fmt.Errorf("purl does not contain version, skipping deps.dev query: %s", purl)
	}

	versionKey, err := getVersionKey(packageInput.Type, packageInput.Namespace, packageInput.Name, packageInput.Version)
	if err != nil {
		logger.Infof("failed to getVersionKey with the following error: %v", err)
		return nil, nil, fmt.Errorf("failed to getVersionKey with the following error: %v", err)
	}

	// Create a request to fetch dependencies
	dependenciesReq := &pb.GetDependenciesRequest{
		VersionKey: versionKey,
	}

	// Fetch dependencies
	deps, err := d.client.GetDependencies(ctx, dependenciesReq)
	if err != nil {
		logger.Infof("failed to get dependencies for version key: %v, error: %v", dependenciesReq.VersionKey, err)
		return nil, nil, fmt.Errorf("failed to get dependencies for version key: %v, error: %v", dependenciesReq.VersionKey, err)
	}

	var dependencyNodes []*PackageComponent

	var batchRequests []*pb.PurlLookupRequest

	for i, node := range deps.Nodes {
		// Skip the root node
		if i == 0 {
			continue
		}

		pkgtype := ""
		if node.VersionKey.System.String() == goUpperCase {
			pkgtype = golang
		} else {
			pkgtype = strings.ToLower(node.VersionKey.System.String())
		}

		depPurl := "pkg:" + pkgtype + "/" + node.VersionKey.Name + "@" + node.VersionKey.Version

		// Check if dependent package purl has already been queried
		if foundDepVal, ok := d.checkedPurls[depPurl]; ok {
			// If found, return the source as nothing as it has already been ingested once
			foundDepVal.Source = nil
			logger.Debugf("dependent package purl %s already queried", depPurl)

			dependencyNodes = append(dependencyNodes, foundDepVal)
			continue
		}

		batchRequests = append(batchRequests, &pb.PurlLookupRequest{Purl: depPurl})
	}

	// Create batch request
	batchReq := &pb.PurlLookupBatchRequest{
		Requests: batchRequests,
	}

	// Send batch request
	purlBatchResp, err := d.client.PurlLookupBatch(ctx, batchReq)
	if err != nil {
		logger.Infof("failed to lookup purls in batch: %v", err)
		return nil, nil, fmt.Errorf("failed to lookup purls in batch: %v", err)
	}

	components, err := d.collectAdditionalMetadata(ctx, purlBatchResp.Responses)
	if err != nil {
		logger.Debugf("failed to get additional metadata for packages, err: %v", err)
	}

	for depPurl, depComponent := range components {
		dependencyNodes = append(dependencyNodes, depComponent)
		d.checkedPurls[depPurl] = depComponent
	}

	return dependencyNodes, deps, nil
}

func (d *depsCollector) collectAdditionalMetadata(ctx context.Context, responses []*pb.PurlLookupBatchResult_Response) (map[string]*PackageComponent, error) {
	type pkgValues struct {
		_type     string
		namespace string
		name      string
	}

	logger := logging.FromContext(ctx)
	var versionKeys []*pb.VersionKey
	versionKeyToPurl := make(map[string]string)
	purlToComponent := make(map[string]*PackageComponent)
	projectIdToPurl := make(map[string]string)
	purlToPkgValues := make(map[string]pkgValues)

	// Collect version keys for batch request
	for _, resp := range responses {
		if resp.Result == nil {
			logger.Infof("no valid result found for purl: %s", resp.Request.Purl)
			continue
		}

		purl := resp.Request.Purl
		component := &PackageComponent{}
		packageInput, err := helpers.PurlToPkg(purl)
		if err != nil {
			logger.Infof("failed to parse purl to pkg: %s", purl)
			continue
		}

		if packageInput != nil && *packageInput.Version == "" {
			logger.Infof("purl does not contain version, skipping deps.dev query: %s", purl)
			continue
		}

		var versionKey *pb.VersionKey
		if resp.Result.Version != nil {
			versionKey = resp.Result.Version.VersionKey
		} else if resp.Result.Package != nil {
			// Handle the case where the result is a package without a version
			logger.Infof("purl %s is a package without a version", purl)
			continue
		} else {
			logger.Infof("no valid result found for purl: %s", purl)
			continue
		}

		versionKeys = append(versionKeys, versionKey)
		component.CurrentPackage = packageInput
		purlToComponent[purl] = component
		versionKeyToPurl[versionKey.String()] = purl
		d.checkedPurls[purl] = component

		// Create project identifier
		pkgType := packageInput.Type
		namespace := packageInput.Namespace
		name := packageInput.Name

		purlToPkgValues[purl] = pkgValues{
			_type:     pkgType,
			namespace: *namespace,
			name:      name,
		}

		projectId := strings.TrimSuffix(*namespace, "/") + "/" + name
		projectIdToPurl[projectId] = purl
	}

	// Create batch request for versions
	batchReq := &pb.GetVersionBatchRequest{
		Requests: make([]*pb.GetVersionRequest, len(versionKeys)),
	}
	for i, key := range versionKeys {
		batchReq.Requests[i] = &pb.GetVersionRequest{VersionKey: key}
	}

	// Send batch request
	versionBatchResp, err := d.client.GetVersionBatch(ctx, batchReq)
	if err != nil {
		logger.Infof("failed to get versions in batch: %v", err)
		return nil, err
	}

	var projectKeys []*pb.ProjectKey

	for _, resp := range versionBatchResp.Responses {
		if resp.Version == nil {
			logger.Infof("no valid version found for version key: %v", resp.Request.VersionKey)
			continue
		}

		// Find the corresponding purl using the version key
		purl, exists := versionKeyToPurl[resp.Version.VersionKey.String()]
		if !exists {
			logger.Infof("no purl found for version key: %v", resp.Version.VersionKey)
			continue
		}

		// Find the corresponding component using the purl
		component, exists := purlToComponent[purl]
		if !exists {
			logger.Infof("no component found for purl: %s", purl)
			continue
		}

		for _, link := range resp.Version.Links {
			if link.Label == sourceRepo {
				src, err := helpers.VcsToSrc(link.Url)
				if err != nil {
					logger.Infof("unable to parse source url: %v, error: %v", link.Url, err)
					continue
				}

				curPkgValues := purlToPkgValues[purl]

				// check if source has already been ingest for this package (without version), if not add source to be ingest for hasSourceAt
				// HasSourceAt is done at the pkgName level for all entries from deps.dev as it does not specify a tag or commit for each version
				// of the package being ingested
				purlWithoutVersion := "pkg:" + curPkgValues._type + "/" + strings.TrimSuffix(curPkgValues.namespace, "/") + "/" + curPkgValues.name
				if _, ok := d.ingestedSource[purlWithoutVersion]; !ok {
					component.Source = src
					d.ingestedSource[purlWithoutVersion] = src
				}

				projectKey := &pb.ProjectKey{
					Id: strings.TrimSuffix(src.Namespace, "/") + "/" + src.Name,
				}
				projectKeys = append(projectKeys, projectKey)
			}
		}

		purlToComponent[purl] = component
	}

	projects, err := d.fetchProjectBatch(ctx, projectKeys)
	if err != nil {
		logger.Errorf("failed to fetch project batch: %v", err)
		return nil, fmt.Errorf("failed to fetch project batch, err: %v", err)
	}

	currentTime := time.Now().UTC()

	for _, project := range projects {
		purl := projectIdToPurl[project.ProjectKey.Id]
		component := purlToComponent[purl]
		if project.Scorecard != nil {
			component.Scorecard = &model.ScorecardInputSpec{}
			component.Scorecard.AggregateScore = float64(project.Scorecard.OverallScore)
			component.Scorecard.ScorecardCommit = project.Scorecard.Scorecard.Commit
			component.Scorecard.ScorecardVersion = project.Scorecard.Scorecard.Version
			component.Scorecard.TimeScanned = project.Scorecard.Date.AsTime().UTC()
			var inputChecks []model.ScorecardCheckInputSpec

			for _, check := range project.Scorecard.Checks {
				inputCheck := model.ScorecardCheckInputSpec{
					Check: check.Name,
					Score: int(check.Score),
				}
				inputChecks = append(inputChecks, inputCheck)
			}
			component.Scorecard.Checks = inputChecks
		}

		// add time when data was obtained
		component.UpdateTime = currentTime

		purlToComponent[purl] = component
	}

	return purlToComponent, nil
}

func (d *depsCollector) fetchProjectBatch(ctx context.Context, projectKeys []*pb.ProjectKey) ([]*pb.Project, error) {
	batchReq := &pb.GetProjectBatchRequest{
		Requests: make([]*pb.GetProjectRequest, len(projectKeys)),
	}
	for i, key := range projectKeys {
		batchReq.Requests[i] = &pb.GetProjectRequest{ProjectKey: key}
	}

	batchResp, err := d.client.GetProjectBatch(ctx, batchReq)
	if err != nil {
		return nil, err
	}

	projects := make([]*pb.Project, len(batchResp.Responses))
	for i, resp := range batchResp.Responses {
		projects[i] = resp.Project
	}
	return projects, nil
}

func (d *depsCollector) fetchVersionBatch(ctx context.Context, versionKeys []*pb.VersionKey) ([]*pb.Version, error) {
	batchReq := &pb.GetVersionBatchRequest{
		Requests: make([]*pb.GetVersionRequest, len(versionKeys)),
	}
	for i, key := range versionKeys {
		batchReq.Requests[i] = &pb.GetVersionRequest{VersionKey: key}
	}

	batchResp, err := d.client.GetVersionBatch(ctx, batchReq)
	if err != nil {
		return nil, err
	}

	versions := make([]*pb.Version, len(batchResp.Responses))
	for i, resp := range batchResp.Responses {
		versions[i] = resp.Version
	}
	return versions, nil
}

func getVersionKey(pkgType string, namespace *string, name string, version *string) (*pb.VersionKey, error) {
	queryName := ""
	if pkgType != maven {
		if namespace != nil && *namespace != "" {
			queryName = strings.TrimSuffix(*namespace, "/") + "/" + name
		} else {
			queryName = name
		}
	} else {
		if namespace != nil && *namespace != "" {
			queryName = strings.TrimSuffix(*namespace, ":") + ":" + name
		} else {
			queryName = name
		}
	}

	sys, err := parseSystem(pkgType)
	if err != nil {
		return nil, err
	}
	versionKey := &pb.VersionKey{
		System:  sys,
		Name:    queryName,
		Version: *version,
	}
	return versionKey, nil
}

// parseSystem returns the pb.System value represented by the argument string.
func parseSystem(name string) (pb.System, error) {
	systemType := ""
	if name == golang {
		systemType = goUpperCase
	} else {
		systemType = strings.ToUpper(name)
	}
	sys, ok := pb.System_value[systemType]
	if !ok {
		return pb.System_SYSTEM_UNSPECIFIED, fmt.Errorf("unknown Insights system %q", name)
	}
	return pb.System(sys), nil
}

// Type returns the collector type
func (d *depsCollector) Type() string {
	return DepsCollector
}

// getProjects fetches project info concurrently for a channel of Inputs.
// It returns a map of project URL to project info.
func (d *depsCollector) getProjects(ctx context.Context, inputChannel <-chan *pb.ProjectKey) map[string]*pb.Project {
	projectMap := sync.Map{}
	var waitGroup sync.WaitGroup

	for input := range inputChannel {
		go func(input *pb.ProjectKey) {
			defer waitGroup.Done()

			project, fetchErr := d.getProject(ctx, input)
			if fetchErr != nil {
				return
			}
			projectMap.Store(input, project)
		}(input)
		waitGroup.Add(1)
	}

	waitGroup.Wait() // wait for all goroutines to finish
	projectMapCopy := make(map[string]*pb.Project)
	projectMap.Range(func(projectURL, projectInfo interface{}) bool {
		key := projectURL.(*pb.ProjectKey) //nolint:forcetypeassert
		projectKey := key.String()
		projectMapCopy[projectKey] = projectInfo.(*pb.Project) //nolint:forcetypeassert
		return true
	})
	return projectMapCopy
}

// getVersions fetches version info concurrently for a channel of Inputs.
// It returns a map of version URL to version info.
func (d *depsCollector) getVersions(ctx context.Context, inputs <-chan *pb.VersionKey,
	projectChan chan *pb.ProjectKey,
) map[string]*pb.Version {
	// this function also sends the project key to the projectChan
	versionsMap := sync.Map{}
	var wg sync.WaitGroup

	for input := range inputs {
		input := input
		wg.Add(1)

		go func() {
			defer wg.Done()

			packageVersion, err := d.getVersion(ctx, input)
			if err != nil {
				return
			}
			projectKey := d.projectKey(packageVersion)
			// if projectKey is nil, it means that the packageVersion does not have a source repo
			if projectKey != nil {
				// send the project key to the projectChan to be fetched concurrently
				projectChan <- projectKey
			}
			versionsMap.Store(input, packageVersion)
		}()
	}

	wg.Wait()
	versionMapCopy := make(map[string]*pb.Version)
	versionsMap.Range(func(packageName, versionInfo interface{}) bool {
		key := packageName.(*pb.VersionKey) //nolint:forcetypeassert
		pName := key.String()
		versionMapCopy[pName] = versionInfo.(*pb.Version) //nolint:forcetypeassert
		return true
	})
	return versionMapCopy
}

// getProject fetches project info for a given project URL.
func (d *depsCollector) getProject(ctx context.Context, v *pb.ProjectKey) (*pb.Project, error) {
	defer d.Metrics.MeasureFunctionExecutionTime(ctx, GetProjectDurationHistogram) // nolint:errcheck
	return d.client.GetProject(ctx, &pb.GetProjectRequest{
		ProjectKey: v,
	})
}

// getVersions fetches version info from deps.dev.
func (d *depsCollector) getVersion(ctx context.Context, v *pb.VersionKey) (*pb.Version, error) {
	defer d.Metrics.MeasureFunctionExecutionTime(ctx, "getVersion") // nolint:errcheck
	return d.client.GetVersion(ctx, &pb.GetVersionRequest{
		VersionKey: v,
	})
}

func (d *depsCollector) projectKey(versionResponse *pb.Version) *pb.ProjectKey {
	// There will be a link with the label "SOURCE_REPO" which will contain the source URL.
	// There cannot be more than one link with the same label.
	for _, link := range versionResponse.Links {
		if link.Label == sourceRepo {
			src, err := helpers.VcsToSrc(link.Url)
			if err != nil {
				continue
			}

			projectReq := &pb.GetProjectRequest{
				ProjectKey: &pb.ProjectKey{
					Id: strings.TrimSuffix(src.Namespace, "/") + "/" + src.Name,
				},
			}
			return projectReq.ProjectKey
		}
	}
	return nil
}

// registerMetrics registers the Metrics for the collector.
func registerMetrics(ctx context.Context, m metrics.MetricCollector) error {
	// Registering counter for get version errors
	if _, err := m.RegisterCounter(ctx, GetVersionErrorsCounter, "pkgtype", "namespace", "name"); err != nil {
		return fmt.Errorf("failed to register counter for get version errors: %w", err)
	}
	return nil
}

// DeregisterCollector deregisters the collector
func (d *depsCollector) DeregisterCollector(collectorType string) error {
	// The DeregisterCollector is a placeholder for removing the metrics from the collector.
	// This is also placeholder for removing state from the collector reference.
	return nil
}

// registerMetricsOnce registers the Metrics for the collector once.
func registerMetricsOnce(ctx context.Context, metricsCollector metrics.MetricCollector) error {
	var err error
	registerOnce.Do(func() {
		err = registerMetrics(ctx, metricsCollector)
	})
	return err
}
