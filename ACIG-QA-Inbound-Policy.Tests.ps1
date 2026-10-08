# Requires Pester 5 and Windows PowerShell 5.1 or PowerShell 7 on Windows
BeforeAll {
    $script:policyPath = Join-Path $PSScriptRoot 'ACIG-QA-Inbound-Policy.xml'
    $script:raw = Get-Content -Raw -Path $script:policyPath

    # Pulls a C# expression body out of the policy and decodes XML entities
    function script:Get-ExprBody([string]$Pattern) {
        $m = [regex]::Match($script:raw, $Pattern, 'Singleline')
        if (-not $m.Success) { throw "Pattern not found in policy: $Pattern" }
        [System.Net.WebUtility]::HtmlDecode($m.Groups[1].Value)
    }

    $b64Body     = Get-ExprBody 'name="b64"\s+value="@\{(.*?)\}"\s*/>'
    $subjectBody = Get-ExprBody 'name="subject"\s+value="@\{(.*?)\}"\s*/>'
    $cnBody      = Get-ExprBody 'name="cn"\s+value="@\{(.*?)\}"\s*/>'
    $condBody    = Get-ExprBody '<when condition="@\((.*?)\)">'

    # Minimal stand-in for the APIM "context" object
    $source = @'
using System;
using System.Collections.Generic;
using System.Linq;
namespace PolicyHarness {
  public class Hdrs {
    public Dictionary<string,string> D = new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
    public string GetValueOrDefault(string n, string d) { string v; return D.TryGetValue(n, out v) ? v : d; }
  }
  public class Req { public Hdrs Headers = new Hdrs(); }
  public class Vars {
    public Dictionary<string,object> D = new Dictionary<string,object>();
    public object this[string k] { get { return D[k]; } }
    public T GetValueOrDefault<T>(string k, T d) { object v; return D.TryGetValue(k, out v) ? (T)v : d; }
  }
  public class Ctx { public Req Request = new Req(); public Vars Variables = new Vars(); }
  public static class Expr {
    public static string B64(Ctx context) { @@B64@@ }
    public static string Subject(Ctx context) { @@SUBJECT@@ }
    public static string Cn(Ctx context) { @@CN@@ }
    public static bool Allowed(Ctx context) { return @@COND@@; }
  }
}
'@
    $source = $source.Replace('@@B64@@', $b64Body).Replace('@@SUBJECT@@', $subjectBody).
                      Replace('@@CN@@', $cnBody).Replace('@@COND@@', $condBody)

    # Add-Type cannot redefine a type inside one session
    if (-not ('PolicyHarness.Expr' -as [type])) { Add-Type -TypeDefinition $source }

    # Runs the b64 and subject steps for a given header value
    function script:New-Ctx($Header) {
        $c = [PolicyHarness.Ctx]::new()
        if ($null -ne $Header) { $c.Request.Headers.D['X-Client-Cert'] = $Header }
        $c.Variables.D['b64']     = [PolicyHarness.Expr]::B64($c)
        $c.Variables.D['subject'] = [PolicyHarness.Expr]::Subject($c)
        $c
    }

    # Mirrors the policy flow: 401, then parse, then 200 or 403. Any exception is a 500.
    function script:Get-Decision($Header, $Expected = 'expected.example.com', $ExpectedAcig = 'acig.example.com') {
        if ($null -eq $Header) { return 401 }
        try {
            $c = New-Ctx $Header
            $c.Variables.D['cn']             = [PolicyHarness.Expr]::Cn($c)
            $c.Variables.D['expectedCN']     = $Expected
            $c.Variables.D['expectedACIGCN'] = $ExpectedAcig
            if ([PolicyHarness.Expr]::Allowed($c)) { 200 } else { 403 }
        }
        catch { 500 }
    }

    function script:New-TestCert([string]$Subject, [datetime]$NotBefore = (Get-Date).AddDays(-1), [datetime]$NotAfter = (Get-Date).AddDays(30)) {
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)
        $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            $Subject, $rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $req.CreateSelfSigned($NotBefore, $NotAfter)
    }

    function script:ConvertTo-Pem($Cert) {
        $b64   = [Convert]::ToBase64String($Cert.RawData)
        $lines = [regex]::Matches($b64, '.{1,64}') | ForEach-Object Value
        "-----BEGIN CERTIFICATE-----`n$($lines -join "`n")`n-----END CERTIFICATE-----"
    }

    # Encoded the way a gateway forwards it in a header
    function script:ConvertTo-HeaderValue($Cert) { [uri]::EscapeDataString((ConvertTo-Pem $Cert)) }
}

Describe "Policy structure (static)" {

    It "Declares all four sections" -ForEach 'inbound', 'backend', 'outbound', 'on-error' {
        $script:raw | Should -Match "<$_>"
        $script:raw | Should -Match "</$_>"
    }

    It "Is well-formed XML" {
        # Fails if '&&' or '<' are not escaped inside attribute values
        { [xml]$script:raw } | Should -Not -Throw
    }

    It "Requires X-Client-Cert and returns 401 when it is missing" {
        $script:raw | Should -Match '<check-header name="X-Client-Cert"[^>]*failed-check-httpcode="401"'
    }

    It "Checks the header before reading it" {
        $script:raw.IndexOf('<check-header') | Should -BeLessThan $script:raw.IndexOf('name="b64"')
    }

    It "Deletes the certificate header only after the certificate was read" {
        $del = $script:raw.IndexOf('<set-header name="X-Client-Cert" exists-action="delete"')
        $del | Should -BeGreaterThan $script:raw.IndexOf('name="subject"')
    }

    It "Removes the api-version query parameter" {
        $script:raw | Should -Match '<set-query-parameter name="api-version" exists-action="delete"'
    }

    It "Sets the backend and rewrites the URI only inside the <when> branch" {
        $when = $script:raw.IndexOf('<when'); $other = $script:raw.IndexOf('<otherwise>')
        $backend = $script:raw.IndexOf('<set-backend-service'); $rewrite = $script:raw.IndexOf('<rewrite-uri')
        $backend | Should -BeGreaterThan $when; $backend | Should -BeLessThan $other
        $rewrite | Should -BeGreaterThan $when; $rewrite | Should -BeLessThan $other
        ([regex]::Matches($script:raw, '<set-backend-service')).Count | Should -Be 1
    }

    It "Returns 403 in the <otherwise> branch" {
        $script:raw | Should -Match '(?s)<otherwise>.*<set-status code="403".*</otherwise>'
    }

    It "Compares the CN case-insensitively against both expected names" {
        $script:raw | Should -Match 'OrdinalIgnoreCase'
        $script:raw | Should -Match '"expectedCN"'
        $script:raw | Should -Match '"expectedACIGCN"'
    }

    It "Uses the named value {{<_>}}" -ForEach @(
        'B2B-QA-ACIG-Inbound-serviceName'
        'B2B-ESP-STG-QA-HAL-SSLCertificateCN'
        'B2B-QA-ACIG-CertificateCN'
        'B2B-QA-ORACLESOA-BaseURL'
        'B2B-QA-ORACLESOA-RewriteURI'
    ) {
        $script:raw | Should -Match ([regex]::Escape("{{$_}}"))
    }

    It "Sets the <_> error header in on-error" -ForEach 'ErrorSource', 'ErrorReason', 'ErrorMessage', 'ErrorScope', 'ErrorSection', 'ErrorPath', 'ErrorPolicyId', 'ErrorStatusCode' {
        $script:raw | Should -Match "(?s)<on-error>.*<set-header name=`"$_`" exists-action=`"override`""
    }

    It "Keeps <base /> in on-error" {
        $script:raw | Should -Match '(?s)<on-error>.*<base />\s*</on-error>'
    }
}

Describe "b64 step (header cleanup)" {

    It "Returns an empty string when the header is absent" {
        (New-Ctx $null).Variables['b64'] | Should -Be ''
    }

    It "Strips the BEGIN/END markers and whitespace" {
        $pem = "-----BEGIN CERTIFICATE-----`nQUJD`nREVG`n-----END CERTIFICATE-----"
        (New-Ctx $pem).Variables['b64'] | Should -Be 'QUJDREVG'
    }

    It "Handles lowercase markers" {
        $pem = "-----begin certificate-----`nQUJD`n-----end certificate-----"
        (New-Ctx $pem).Variables['b64'] | Should -Be 'QUJD'
    }

    It "URL-decodes a percent-encoded PEM" {
        $pem = [uri]::EscapeDataString("-----BEGIN CERTIFICATE-----`nQUJD`nREVG`n-----END CERTIFICATE-----")
        (New-Ctx $pem).Variables['b64'] | Should -Be 'QUJDREVG'
    }

    It "Accepts a bare base64 value without markers" {
        (New-Ctx "QUJD REVG").Variables['b64'] | Should -Be 'QUJDREVG'
    }

    It "KNOWN ISSUE: corrupts an unencoded PEM whose base64 contains '+'" {
        # '+' triggers UrlDecode, which turns it into a space that is then stripped.
        # Correct behaviour would be 'AB+/'.
        $pem = "-----BEGIN CERTIFICATE-----`nAB+/`n-----END CERTIFICATE-----"
        (New-Ctx $pem).Variables['b64'] | Should -Be 'AB/'
    }
}

Describe "subject step (certificate parsing)" {

    It "Returns '<empty b64>' when there is nothing to parse" {
        (New-Ctx $null).Variables['subject'] | Should -Be '<empty b64>'
    }

    It "Returns a 'Parse error' message for invalid base64" {
        (New-Ctx 'not base64 !!!').Variables['subject'] | Should -Match '^Parse error'
    }

    It "Returns a 'Parse error' message for valid base64 that is not a certificate" {
        (New-Ctx 'QUJDREVG').Variables['subject'] | Should -Match '^Parse error'
    }

    It "Returns the subject of a real certificate" {
        $cert = New-TestCert 'CN=partner.example.com, O=Partner'
        (New-Ctx (ConvertTo-HeaderValue $cert)).Variables['subject'] | Should -Match 'CN=partner\.example\.com'
    }
}

Describe "cn step (CN extraction)" {

    It "Extracts the CN from '<Subject>'" -ForEach @(
        @{ Subject = 'CN=partner.example.com, O=Partner'; Expected = 'partner.example.com' }
        @{ Subject = 'CN=partner.example.com';            Expected = 'partner.example.com' }
        @{ Subject = 'CN= spaced.example.com ,O=X';       Expected = 'spaced.example.com' }
    ) {
        $c = [PolicyHarness.Ctx]::new(); $c.Variables.D['subject'] = $Subject
        [PolicyHarness.Expr]::Cn($c) | Should -Be $Expected
    }

    It "KNOWN LIMITATION: returns the wrong value when CN is not the first RDN" {
        $c = [PolicyHarness.Ctx]::new(); $c.Variables.D['subject'] = 'O=Partner, CN=partner.example.com'
        [PolicyHarness.Expr]::Cn($c) | Should -Be 'Partner'
    }

    It "KNOWN LIMITATION: truncates a CN that contains a comma" {
        $c = [PolicyHarness.Ctx]::new(); $c.Variables.D['subject'] = 'CN="Doe, John", O=X'
        [PolicyHarness.Expr]::Cn($c) | Should -Be '"Doe'
    }

    It "KNOWN ISSUE: throws for '<Subject>' instead of denying cleanly" -ForEach @(
        @{ Subject = '<empty b64>' }
        @{ Subject = 'Parse error: bad data' }
    ) {
        $c = [PolicyHarness.Ctx]::new(); $c.Variables.D['subject'] = $Subject
        { [PolicyHarness.Expr]::Cn($c) } | Should -Throw
    }
}

Describe "Access decision (condition)" {

    It "Returns <Expected> for CN '<Cn>'" -ForEach @(
        @{ Cn = 'expected.example.com';          Expected = $true  }
        @{ Cn = 'acig.example.com';              Expected = $true  }
        @{ Cn = 'EXPECTED.EXAMPLE.COM';          Expected = $true  }
        @{ Cn = 'Acig.Example.Com';              Expected = $true  }
        @{ Cn = 'other.example.com';             Expected = $false }
        @{ Cn = 'expected.example.com.evil.com'; Expected = $false }
        @{ Cn = 'xexpected.example.com';         Expected = $false }
        @{ Cn = '';                              Expected = $false }
    ) {
        $c = [PolicyHarness.Ctx]::new()
        $c.Variables.D['cn'] = $Cn
        $c.Variables.D['expectedCN'] = 'expected.example.com'
        $c.Variables.D['expectedACIGCN'] = 'acig.example.com'
        [PolicyHarness.Expr]::Allowed($c) | Should -Be $Expected
    }
}

Describe "End-to-end decision (real certificates)" {

    It "401 when the header is missing" {
        Get-Decision $null | Should -Be 401
    }

    It "200 for a certificate with the expected CN" {
        Get-Decision (ConvertTo-HeaderValue (New-TestCert 'CN=expected.example.com, O=HAL')) | Should -Be 200
    }

    It "200 for a certificate with the ACIG CN" {
        Get-Decision (ConvertTo-HeaderValue (New-TestCert 'CN=acig.example.com')) | Should -Be 200
    }

    It "200 for a certificate with the CN in a different case" {
        Get-Decision (ConvertTo-HeaderValue (New-TestCert 'CN=Expected.Example.COM')) | Should -Be 200
    }

    It "403 for a certificate with an unknown CN" {
        Get-Decision (ConvertTo-HeaderValue (New-TestCert 'CN=attacker.example.com')) | Should -Be 403
    }

    It "403 for a CN that only contains the expected name" {
        Get-Decision (ConvertTo-HeaderValue (New-TestCert 'CN=expected.example.com.evil.com')) | Should -Be 403
    }

    It "Allows a plain (unencoded) PEM when its base64 has no '+'" {
        # Retries until a certificate without '+' is generated
        $pem = $null
        1..20 | ForEach-Object {
            if (-not $pem) {
                $p = ConvertTo-Pem (New-TestCert 'CN=expected.example.com')
                if ($p -notmatch '\+') { $pem = $p }
            }
        }
        if (-not $pem) { Set-ItResult -Skipped -Because 'could not generate a certificate without +'; return }
        Get-Decision $pem | Should -Be 200
    }

    It "KNOWN GAP: allows an expired certificate with the expected CN" {
        $cert = New-TestCert 'CN=expected.example.com' (Get-Date).AddDays(-60) (Get-Date).AddDays(-30)
        Get-Decision (ConvertTo-HeaderValue $cert) | Should -Be 200
    }

    It "KNOWN GAP: allows a self-signed certificate (no chain validation)" {
        Get-Decision (ConvertTo-HeaderValue (New-TestCert 'CN=expected.example.com')) | Should -Be 200
    }

    It "KNOWN ISSUE: garbage in the header causes an exception (500), not 403" {
        Get-Decision 'garbage' | Should -Be 500
    }

    It "KNOWN ISSUE: an empty header value causes an exception (500), not 401 or 403" {
        Get-Decision '' | Should -Be 500
    }
}

# Needs a deployed API. Set APIM_URL, and optionally APIM_KEY, APIM_CERT_OK_CN, APIM_CERT_BAD_CN (requires PowerShell 7).
Describe "APIM integration" -Skip:(-not $env:APIM_URL) {

    BeforeAll {
        function script:Send($Header) {
            $h = @{}
            if ($env:APIM_KEY) { $h['Ocp-Apim-Subscription-Key'] = $env:APIM_KEY }
            if ($Header) { $h['X-Client-Cert'] = $Header }
            Invoke-WebRequest -Uri $env:APIM_URL -Headers $h -Method Post -Body '{}' -ContentType 'application/json' -SkipHttpErrorCheck
        }
    }

    It "Returns 401 without the certificate header" {
        (Send $null).StatusCode | Should -Be 401
    }

    It "Returns 403 for a certificate with an unknown CN" {
        $cert = New-TestCert 'CN=attacker.example.com'
        (Send (ConvertTo-HeaderValue $cert)).StatusCode | Should -Be 403
    }

    It "Does not return 401 or 403 for the expected CN" -Skip:(-not $env:APIM_CERT_OK_CN) {
        $cert = New-TestCert "CN=$($env:APIM_CERT_OK_CN)"
        (Send (ConvertTo-HeaderValue $cert)).StatusCode | Should -Not -BeIn 401, 403
    }
}