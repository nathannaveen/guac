package main

import (
	"context"
	"fmt"
	"github.com/Khan/genqlient/graphql"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/logging"
	"net/http"
	"sort"
)

type dependency struct {
	id            string
	name          string // the name of the dependency including the sub-path and the qualifiers
	numDependents int    // number of packages that depend on this package
}

func main() {
	graphqlEndpoint := "http://localhost:8080/query"

	httpClient := http.Client{}
	client := graphql.NewClient(graphqlEndpoint, &httpClient)

	ctx := context.Background()
	logger := logging.FromContext(ctx)

	pkgResponse, err := model.Packages(ctx, client, model.PkgSpec{})
	if err != nil {
		logger.Fatalf("error querying for package: %v", err)
	}
	if len(pkgResponse.Packages) < 1 {
		logger.Fatalf("failed to located package based on purl")
	}

	var packages []dependency
	pkgIdsToIndex := make(map[string]int) // map of the id of the package to the index of the package in packages.

	// memory is used as a DP to avoid re-iterating over packages that we have already seen in a previous iteration
	memory := map[string]dependency{}

	for _, p := range pkgResponse.Packages {
		for _, namespace := range p.Namespaces {
			for _, name := range namespace.Names {
				for _, version := range name.Versions {
					id := version.Id
					packageName := p.Type + "_" + namespace.Namespace + "_" + name.Name

					// We don't want to re-calculate findDependentsDFS on a node that we have already seen because we will
					// have to add the value that we have already calculated to the number of dependencies for that node again.
					if _, alreadyCalculatedNode := memory[id]; !alreadyCalculatedNode {
						// depth is the depth that we want to traverse the tree
						// a depth of -1 means that we traverse the entire tree
						depth := -1
						visited := make(map[string]bool)
						dependencies, _ := findDependentsDFS(ctx, client, id, packageName, model.PkgInputSpec{}, visited, memory, depth)

						for _, d := range dependencies {
							if _, indexOk := pkgIdsToIndex[d.id]; !indexOk {
								packages = append(packages, dependency{
									id:   d.id,
									name: d.name,
								})
								pkgIdsToIndex[d.id] = len(packages) - 1
							}

							if _, ok := memory[d.id]; !ok {
								packages[pkgIdsToIndex[d.id]].numDependents += d.numDependents
							}

							memory[d.id] = d
						}
					}
				}
			}
		}
	}

	// packages and memory have the same information, but packages is an array while memory is a map

	sort.Slice(packages, func(i, j int) bool {
		return packages[i].numDependents > packages[j].numDependents
	})

	fmt.Println("IDs : the number of dependencies : the package name")
	fmt.Println("---------------------------------------------------")

	for _, d := range packages {
		if d.numDependents > 0 {
			fmt.Println(d.id, d.numDependents, d.name)
		}
	}
}

func findDependentsDFS(ctx context.Context, gqlclient graphql.Client, subjectQueryID, subjectQueryName string, spec model.PkgInputSpec, visited map[string]bool, memory map[string]dependency, depth int) ([]dependency, error) {
	// we need the visited map as well as memory because visited makes sure that we don't re-iterate over a node that we
	// have already visited when starting with a given ID.
	// The memory is for storing the value of nodes that have already been visited when searching for previous starting ID.
	if visited[subjectQueryID] {
		return nil, fmt.Errorf("cycle detected")
	}
	visited[subjectQueryID] = true

	if depth == 0 {
		return []dependency{
			{
				id:   subjectQueryID,
				name: subjectQueryName,
			},
		}, nil
	}

	if val, ok := memory[subjectQueryID]; ok {
		return []dependency{val}, nil
	}

	var res []dependency

	curDependent := dependency{
		id:            subjectQueryID,
		name:          subjectQueryName,
		numDependents: 0,
	}

	dependencyResponse, err := model.IsDependencies(ctx, gqlclient, []model.PkgInputSpec{}, []model.PkgInputSpec{spec}, model.MatchFlags{}, nil)
	for _, dep := range dependencyResponse.IngestDependencies {
		fmt.Println(dep)
	}
	if err != nil {
		return nil, err
	}

	neighborResponse, err := model.Neighbors(ctx, gqlclient, subjectQueryID, []model.Edge{})
	if err != nil {
		return nil, fmt.Errorf("error querying neighbors: %v", err)
	}

	// A depth of -1 means that we traverse through the entire graph
	// and a depth of 0 means that we stop traversing the graph
	// We keep moving through the graph for any other depth other than 0.
	newDepth := max(depth-1, -1)

	for _, neighbor := range neighborResponse.Neighbors {
		switch neighborType := neighbor.(type) {
		case *model.NeighborsNeighborsIsDependency:
			// check whether we are going up the tree, and not back down
			depNamespaceNames := neighborType.DependencyPackage.Namespaces
			if len(depNamespaceNames) > 0 && len(depNamespaceNames[0].Names) > 0 &&
				len(depNamespaceNames[0].Names[0].Versions) > 0 &&
				depNamespaceNames[0].Names[0].Versions[0].Id == subjectQueryID {

				namespaceNames := neighborType.Package.Namespaces[0].Names[0]

				name := neighborType.Package.Type + "_" + neighborType.Package.Namespaces[0].Namespace + "_" + namespaceNames.Name

				var qualifiers []model.PackageQualifierInputSpec
				for _, q := range namespaceNames.Versions[0].Qualifiers {
					qualifiers = append(qualifiers, model.PackageQualifierInputSpec{
						Key:   q.Key,
						Value: q.Value,
					})
				}

				s := model.PkgInputSpec{
					Type:       neighborType.Package.Type,
					Namespace:  &neighborType.Package.Namespaces[0].Namespace,
					Name:       namespaceNames.Name,
					Version:    &namespaceNames.Versions[0].Version,
					Qualifiers: qualifiers,
					Subpath:    &namespaceNames.Versions[0].Subpath,
				}

				dependentsDFS, err := findDependentsDFS(ctx, gqlclient, namespaceNames.Versions[0].Id, name, s, visited, memory, newDepth)
				if err != nil {
					return nil, err
				}

				for _, d := range dependentsDFS {
					curDependent.numDependents += d.numDependents
				}
				curDependent.numDependents += 1

				res = append(res, dependentsDFS...)
			}
		default:
			continue
		}
	}

	res = append(res, curDependent)

	return res, nil
}
