package helpers

import (
	"context"
	"fmt"
	"github.com/Khan/genqlient/graphql"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/logging"
	"go.uber.org/zap"
)

func FindLicensesInSBOM(ctx context.Context, client graphql.Client, sbom *model.AllHasSBOMTree) ([]model.CertifyLegalCertifyLegal, error) {
	logger := logging.FromContext(ctx)
	var certifyLegals []model.CertifyLegalCertifyLegal

	for _, software := range sbom.IncludedSoftware {
		switch s := software.(type) {
		case *model.AllHasSBOMTreeIncludedSoftwarePackage:
			id := s.Namespaces[0].Names[0].Versions[0].Id
			l, err := getLicensesForPackage(ctx, client, id, logger)
			if err != nil {
				logger.Errorw("Failed to get certifyLegals for package", "id", id, "error", err)
				return nil, err
			}
			certifyLegals = append(certifyLegals, l...)
		case *model.AllHasSBOMTreeIncludedSoftwareArtifact:
			// convert artifact to pkg, then use the pkg id to get the vulnerability
			pkg, err := getPkgFromArtifact(client, s.Id)
			if err != nil {
				return nil, fmt.Errorf("failed to get package attached to artifact %s: %w", s.Id, err)
			}
			l, err := getLicensesForPackage(ctx, client, pkg.Namespaces[0].Names[0].Versions[0].Id, logger)
			if err != nil {
				logger.Errorw("Failed to get certifyLegals for artifact", "id", s.Id, "error", err)
				return nil, err
			}
			certifyLegals = append(certifyLegals, l...)
		default:
			logger.Warnw("Unknown software type in SBOM", "type", fmt.Sprintf("%T", software))
		}
	}

	return certifyLegals, nil
}

func getLicensesForPackage(ctx context.Context, client graphql.Client, pkgID string, logger *zap.SugaredLogger) ([]model.CertifyLegalCertifyLegal, error) {
	legal, err := model.CertifyLegal(ctx, client, model.CertifyLegalSpec{
		Subject: &model.PackageOrSourceSpec{
			Package: &model.PkgSpec{
				Id: &pkgID,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query vulnerabilities for package %s: %w", pkgID, err)
	}
	return legal.CertifyLegal, nil
}
