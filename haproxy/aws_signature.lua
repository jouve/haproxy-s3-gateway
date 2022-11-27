SIGNED_HEADERS = {"host", "x-amz-content-sha256", "x-amz-date"}

function hmac(txn, digest, message, key)
    return txn.c:hmac(message, digest, txn.c:base64(key))
end

function hex(txn, b)
    return txn.c:lower(txn.c:hex(b))
end

function sha256(txn, content)
    return hex(txn, txn.c:sha2(content, 256))
end

function trim(txn, s)
    return txn.c:rtrim(txn.c:ltrim(s, " "), " ")
end

function sign_s3v2(txn, region, endpoint, access_key, secret_key)
    date = txn.c:http_date(txn.sf:date())
    txn.http:req_set_header("Host", endpoint)
    txn.http:req_set_header("Date", date)
    txn.http:req_set_header(
        "Authorization",
        string.format(
            "AWS %s:%s",
            access_key,
            txn.c:base64(
                hmac(
                    txn,
                    "sha1",
                    table.concat({txn.f:method(), "", "", date, txn.f:path()}, "\n"),
                    secret_key
                )
            )
        )
    )
end

-- https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html

function canonical_headers(txn, headers)
    t = {}
    for a, name in pairs(SIGNED_HEADERS) do
        table.insert(t, string.format("%s:%s\n", txn.c:lower(name), trim(txn, headers[name])))
    end
    return table.concat(t)
end

function canonical_request(txn, endpoint, x_amz_content_sha256, x_amz_date)
    return table.concat(
        {
            txn.f:method(),                     -- HTTPMethod
            txn.f:path(),                       -- CanonicalURI
            "",                                 -- CanonicalQueryString
            canonical_headers(                  -- CanonicalHeaders
                txn,
                {
                    host                     = endpoint,
                    ["x-amz-content-sha256"] = x_amz_content_sha256,
                    ["x-amz-date"]           = x_amz_date
                }
            ),
            table.concat(SIGNED_HEADERS, ";"),  -- SignedHeaders
            x_amz_content_sha256                -- HashedPayload
        },
        "\n"
    )
end

-- https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html

function string_to_sign(txn, x_amz_date, scope, canonical_request)
    return table.concat(
        {
            "AWS4-HMAC-SHA256",            -- Algorithm
            x_amz_date,                    -- RequestDateTime
            scope,                         -- CredentialScope
            sha256(txn, canonical_request) -- HashedCanonicalRequest
        },
        "\n"
    )
end

-- https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html#signing-request-intro

function signing_key(txn, secret_key, date, region)
    date_key = hmac(txn, "sha256", date, string.format("AWS4%s", secret_key))
    date_region_key = hmac(txn, "sha256", region, date_key)
    date_region_service_key = hmac(txn, "sha256", "s3", date_region_key)
    return hmac(txn, "sha256", "aws4_request", date_region_service_key)
end

-- https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-auth-using-authorization-header.html

function sign_s3v4(txn, region, endpoint, access_key, secret_key)
    date = txn.f:date()
    txn.http:req_set_header("Host", endpoint)

    x_amz_date = txn.c:utime(date, "%Y%m%dT%H%M%SZ")
    txn.http:req_set_header("x-amz-date", x_amz_date)

    if txn.f:req_body_size() == 0 then
        x_amz_content_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    else
        x_amz_content_sha256 = sha256(txn, txn.f:req_body())
    end
    txn.http:req_set_header("x-amz-content-sha256", x_amz_content_sha256)

    today = txn.c:utime(date, "%Y%m%d")
    scope = string.format("%s/%s/s3/aws4_request", today, region)

    txn.http:req_set_header(
        "Authorization",
        string.format(
            "AWS4-HMAC-SHA256 Credential=%s/%s,SignedHeaders=%s,Signature=%s",
            access_key,
            scope,
            table.concat(SIGNED_HEADERS, ";"),
            hex(
                txn,
                hmac(
                    txn,
                    "sha256",
                    string_to_sign(txn, x_amz_date, scope, canonical_request(txn, endpoint, x_amz_content_sha256, x_amz_date)),
                    signing_key(txn, secret_key, today, region)
                )
            )
        )
    )
end

core.register_action("sign_s3v2", {"http-req"}, sign_s3v2, 4)
core.register_action("sign_s3v4", {"http-req"}, sign_s3v4, 4)
