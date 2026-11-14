#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export HOMEBREW_NO_AUTO_UPDATE=1
if ! command -v xcodegen >/dev/null 2>&1; then brew install xcodegen; fi
mkdir -p artifacts
if [ -f desktop/public.json ]; then cp desktop/public.json iphone/Resources/Server.json; fi
(cd iphone && xcodegen generate)
xcodebuild -version
xcrun simctl list devices available --json > artifacts/simulators.json
SIMULATOR_ID=$(python3 -c 'import json; x=json.load(open("artifacts/simulators.json")); print(next(d["udid"] for ds in x["devices"].values() for d in ds if d.get("isAvailable") and d["name"].startswith("iPhone")))')
xcodebuild test -project iphone/ENCPTD.xcodeproj -scheme ENCPTD \
  -destination "platform=iOS Simulator,id=$SIMULATOR_ID" \
  -derivedDataPath "$ROOT/build-simulator" \
  -resultBundlePath "$ROOT/artifacts/EncryptionTests.xcresult" \
  CODE_SIGNING_ALLOWED=NO 2>&1 | tee artifacts/tests.log
xcodebuild build -project iphone/ENCPTD.xcodeproj -scheme ENCPTD \
  -configuration Release -sdk iphoneos -destination 'generic/platform=iOS' \
  -derivedDataPath "$ROOT/build" \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY="" DEVELOPMENT_TEAM="" \
  2>&1 | tee artifacts/build.log
mkdir -p artifacts/package/Payload
ditto build/Build/Products/Release-iphoneos/ENCPTD.app artifacts/package/Payload/ENCPTD.app
(cd artifacts/package && /usr/bin/zip -qry ../ENCPTD-unsigned.ipa Payload)
(cd artifacts && shasum -a 256 ENCPTD-unsigned.ipa > ENCPTD-unsigned.ipa.sha256)
