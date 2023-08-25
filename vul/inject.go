//go:build wireinject
// +build wireinject

package vul

import (
	"context"
	"time"

	"github.com/aquasecurity/fanal/cache"
	"github.com/google/wire"
	"github.com/khulnasoft/vul/pkg/rpc/client"
	"github.com/khulnasoft/vul/pkg/scanner"
	"github.com/khulnasoft/vul/pkg/vulnerability"
)

func initializeDockerScanner(ctx context.Context, imageName string, artifactCache cache.ArtifactCache, customHeaders client.CustomHeaders,
	url client.RemoteURL, timeout time.Duration) (scanner.Scanner, func(), error) {
	wire.Build(scanner.RemoteDockerSet)
	return scanner.Scanner{}, nil, nil
}

func initializeVulnerabilityClient() vulnerability.Client {
	wire.Build(vulnerability.SuperSet)
	return vulnerability.Client{}
}
