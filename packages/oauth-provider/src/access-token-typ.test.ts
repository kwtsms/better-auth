import type { GenericEndpointContext } from "@better-auth/core";
import { jwt, signJWT } from "better-auth/plugins/jwt";
import { getTestInstance } from "better-auth/test";
import type { JWTPayload } from "jose";
import { decodeProtectedHeader } from "jose";
import { afterEach, describe, expect, it, vi } from "vitest";
import { oauthProviderResourceClient } from "./client-resource";
import { oauthProvider } from "./oauth";

const origin = "http://localhost:4124";
const issuer = `${origin}/api/auth`;
const resource = "https://api.example.com";

async function setup() {
	const { auth, signInWithTestUser } = await getTestInstance({
		baseURL: origin,
		plugins: [
			jwt(),
			oauthProvider({
				loginPage: "/login",
				consentPage: "/consent",
				resources: [resource],
				enforcePerClientResources: false,
				scopes: ["read:posts"],
				clientPrivileges: () => true,
			}),
		],
	});
	const { headers, user } = await signInWithTestUser();
	const client = await auth.api.adminCreateOAuthClient({
		headers,
		body: {
			token_endpoint_auth_method: "client_secret_post",
			grant_types: ["client_credentials"],
			client_credentials_scopes: ["read:posts"],
		},
	});
	const context = await auth.$context;
	const jwtOptions = context.getPlugin("jwt")?.options;
	/** Signs `payload` with the provider's keys, as app code can. */
	const sign = (payload: JWTPayload, typ?: string) =>
		signJWT({ context } as GenericEndpointContext, {
			options: jwtOptions,
			payload,
			header: typ ? { typ } : undefined,
		});
	/** A payload shaped like an access token for a registered client and resource. */
	const accessTokenShape = (): JWTPayload => ({
		iss: issuer,
		aud: resource,
		azp: client.client_id,
		scope: "read:posts",
		iat: Math.floor(Date.now() / 1000),
	});
	const introspect = (token: string) =>
		auth.api.oauth2Introspect({
			body: {
				token,
				client_id: client.client_id,
				client_secret: client.client_secret,
			},
		});
	const resourceClient = oauthProviderResourceClient(auth).getActions();
	const verifyRequest = (
		token: string,
		opts?: Parameters<typeof resourceClient.verifyAccessTokenRequest>[1],
	) =>
		resourceClient.verifyAccessTokenRequest(
			{
				authorizationHeader: `Bearer ${token}`,
				method: "GET",
				url: `${origin}/api/rpc/thing`,
			},
			{ verifyOptions: { audience: resource }, ...opts },
		);
	return {
		auth,
		client,
		userId: user.id,
		sign,
		accessTokenShape,
		introspect,
		verifyRequest,
	};
}

/**
 * @see https://datatracker.ietf.org/doc/html/rfc9068#section-4
 * @see https://datatracker.ietf.org/doc/html/rfc8725#section-3.11
 */
describe("JWT access tokens require typ at+jwt", async () => {
	const server = await setup();

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it("reports a provider-signed JWT without typ as inactive", async () => {
		const { token } = await server.auth.api.signJWT({
			body: { payload: server.accessTokenShape() },
		});
		expect(decodeProtectedHeader(token).typ).toBeUndefined();

		await expect(server.introspect(token)).resolves.toEqual({ active: false });
	});

	it("reports a provider-signed JWT with typ JWT as inactive", async () => {
		const token = await server.sign(server.accessTokenShape(), "JWT");

		await expect(server.introspect(token)).resolves.toEqual({ active: false });
	});

	it("rejects a JWT without at+jwt at UserInfo", async () => {
		const payload = {
			...server.accessTokenShape(),
			aud: [resource, `${issuer}/oauth2/userinfo`],
			sub: server.userId,
			scope: "openid",
		};
		const userInfo = async (typ: string) =>
			server.auth.api.oauth2UserInfo({
				headers: new Headers({
					authorization: `Bearer ${await server.sign(payload, typ)}`,
				}),
			});

		await expect(userInfo("at+jwt")).resolves.toMatchObject({
			sub: server.userId,
		});
		await expect(userInfo("JWT")).rejects.toMatchObject({ statusCode: 401 });
	});

	it("rejects a JWT without at+jwt at the resource client", async () => {
		const token = await server.sign(server.accessTokenShape(), "JWT");

		await expect(server.verifyRequest(token)).rejects.toMatchObject({
			statusCode: 401,
		});
	});

	it.each(["at+jwt", "application/at+jwt", "AT+JWT", "Application/AT+JWT"])(
		"accepts typ %s as a media type",
		async (typ) => {
			const token = await server.sign(server.accessTokenShape(), typ);

			await expect(server.introspect(token)).resolves.toMatchObject({
				active: true,
				client_id: server.client.client_id,
			});
			await expect(server.verifyRequest(token)).resolves.toMatchObject({
				azp: server.client.client_id,
			});
		},
	);

	it("keeps verifying access tokens from the token endpoint", async () => {
		const tokens = await server.auth.api.oauth2Token({
			body: {
				grant_type: "client_credentials",
				client_id: server.client.client_id,
				client_secret: server.client.client_secret,
				scope: "read:posts",
				resource,
			},
		});
		expect(decodeProtectedHeader(tokens.access_token).typ).toBe("at+jwt");

		await expect(server.introspect(tokens.access_token)).resolves.toMatchObject(
			{ active: true },
		);
		await expect(
			server.verifyRequest(tokens.access_token),
		).resolves.toMatchObject({ azp: server.client.client_id });
	});

	it("lets the resource client override the expected typ", async () => {
		const token = await server.sign(server.accessTokenShape(), "JWT");
		vi.stubGlobal("fetch", (input: RequestInfo | URL, init?: RequestInit) =>
			server.auth.handler(new Request(input, init)),
		);
		await expect(
			server.verifyRequest(token, {
				verifyOptions: { audience: resource, typ: "JWT" },
				jwksUrl: `${issuer}/jwks`,
			}),
		).resolves.toMatchObject({ azp: server.client.client_id });
	});
});

describe("custom JWT signer", () => {
	it("warns at startup that the signer must apply header.typ", async () => {
		const log = vi.fn();
		const { auth } = await getTestInstance({
			baseURL: origin,
			logger: { level: "warn", log },
			plugins: [
				jwt({
					jwks: {
						remoteUrl: "https://keys.example.com/jwks",
						keyPairConfig: { alg: "EdDSA" },
					},
					jwt: { sign: async () => "signed" },
				}),
				oauthProvider({
					loginPage: "/login",
					consentPage: "/consent",
					resources: [resource],
					enforcePerClientResources: false,
				}),
			],
		});
		await auth.$context;

		expect(log).toHaveBeenCalledWith(
			"warn",
			expect.stringContaining("header.typ"),
		);
	});
});
