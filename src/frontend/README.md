# DaffyDefs frontend configuration

`FINALIZER_BASE_URL` is a build-time value for the public
`zd-finalizer-service` origin (for example, an origin with no path or trailing
slash). Its checked-in value is deliberately empty; F3 must supply the deployed
service URL when building the frontend.

The finaliser service's `allowed_origins` CORS configuration must include the
exact deployed DaffyDefs frontend origin. The browser sends JSON `POST` requests,
so the service must allow that origin, the `POST` and `GET` methods, and the
`Content-Type` request header.
