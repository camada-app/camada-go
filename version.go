package camada

// The SDK's wire identity (SDK-03): x-camada-sdk: @camada/go/<version>. This literal is the
// single source: the git tag is the release version, and the sibling drift guards (camada-backend,
// camada-web, camada-mkt) parse this file the way they parse a package.json. Plain X.Y.Z only:
// the analyst's SDK_RE drops anything else.
const Version = "0.1.0"

// SDKID rides every snapshot poll and event batch as x-camada-sdk.
const SDKID = "@camada/go/" + Version
