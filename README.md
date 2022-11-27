# HAProxy s3 gateway

This project provides configuration snippets to configure HAProxy to act as an authenticating gateway for to AWS S3 or another S3 compatible service.
This allows you to proxy a private S3 bucket without requiring users to authenticate to it.

## s3v2

s3v2 backend implements s3v2 signature using pure HAProxy configuration.

## s3v4

s3v4 backend implements s3v4 signature using pure HAProxy configuration.

## s3v2-lua & s3v4-lua

s3v2-lua & s3v4-lua implements s3v2 & s3v4 signature in lua, using HAProxy primitives (ie. converters) for cryptography.

It provides the same features as the pure HAProxy configuration implementation.
