package helpers

import (
	"context"
	"fmt"
	"github.com/Khan/genqlient/graphql"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/logging"
	"go.uber.org/zap"
)

func FindVulnerabilitiesInSBOM(ctx context.Context, client graphql.Client, sbom *model.AllHasSBOMTree) ([]model.CertifyVulnCertifyVuln, error) {
	logger := logging.FromContext(ctx)
	var vulnerabilities []model.CertifyVulnCertifyVuln

	for _, software := range sbom.IncludedSoftware {
		switch s := software.(type) {
		case *model.AllHasSBOMTreeIncludedSoftwarePackage:
			id := s.Namespaces[0].Names[0].Versions[0].Id
			vulns, err := getVulnerabilitiesForPackage(ctx, client, id, logger)
			if err != nil {
				logger.Errorw("Failed to get vulnerabilities for package", "id", id, "error", err)
				return nil, err
			}
			vulnerabilities = append(vulnerabilities, vulns...)
		case *model.AllHasSBOMTreeIncludedSoftwareArtifact:
			// convert artifact to pkg, then use the pkg id to get the vulnerability
			pkg, err := getPkgFromArtifact(client, s.Id)
			if err != nil {
				return nil, fmt.Errorf("failed to get package attached to artifact %s: %w", s.Id, err)
			}
			vulns, err := getVulnerabilitiesForPackage(ctx, client, pkg.Namespaces[0].Names[0].Versions[0].Id, logger)
			if err != nil {
				logger.Errorw("Failed to get vulnerabilities for artifact", "id", s.Id, "error", err)
				return nil, err
			}
			vulnerabilities = append(vulnerabilities, vulns...)
		default:
			logger.Warnw("Unknown software type in SBOM", "type", fmt.Sprintf("%T", software))
		}
	}

	return vulnerabilities, nil
}

func getVulnerabilitiesForPackage(ctx context.Context, client graphql.Client, pkgID string, logger *zap.SugaredLogger) ([]model.CertifyVulnCertifyVuln, error) {
	vulns, err := model.CertifyVuln(ctx, client, model.CertifyVulnSpec{
		Package: &model.PkgSpec{
			Id: &pkgID,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query vulnerabilities %s: %w", pkgID, err)
	}
	return vulns.CertifyVuln, nil
}
