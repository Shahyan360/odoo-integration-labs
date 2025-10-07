param([ValidateSet('init','up','stop','upgrade','seed','reset')][string]$Action='up')
$ErrorActionPreference='Stop'
Set-Location -LiteralPath (Split-Path -Parent $PSScriptRoot)
if (!(Test-Path -LiteralPath '.env')) { python scripts/bootstrap.py; if ($LASTEXITCODE -ne 0) { throw 'Bootstrap failed.' } }
$composeArgs=@('compose','--env-file','.env','-f','docker/compose.yaml')
function Invoke-Lab { & docker @composeArgs @args; if ($LASTEXITCODE -ne 0) { throw 'Docker action failed.' } }
function Seed-Lab { Get-Content -Raw -LiteralPath scripts/seed.py | & docker @composeArgs run --rm -T odoo odoo shell -d integration_demo --no-http; if ($LASTEXITCODE -ne 0) { throw 'Seed failed.' } }
switch ($Action) {
 'init' { Invoke-Lab up -d db mailpit; Invoke-Lab run --rm odoo odoo -d integration_demo -i independent_connectors --without-demo=all --stop-after-init --no-http; Seed-Lab; Invoke-Lab up -d odoo }
 'up' { Invoke-Lab up -d }
 'stop' { Invoke-Lab stop }
 'seed' { Seed-Lab }
 'upgrade' { Invoke-Lab stop odoo; Invoke-Lab run --rm odoo odoo -d integration_demo -u independent_connectors --without-demo=all --stop-after-init --no-http; Invoke-Lab up -d odoo }
 'reset' { Invoke-Lab stop odoo; Invoke-Lab exec -T db dropdb -U lab --if-exists --force integration_demo; & $PSCommandPath -Action init }
}
