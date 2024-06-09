import { Elysia, ValidationError, getSchemaValidator } from 'elysia'

import {
    SignJWT,
    jwtVerify,
    type JWTPayload,
    type JWSHeaderParameters,
    type KeyLike,
    type JWTVerifyOptions
} from 'jose'

import { Type as t } from '@sinclair/typebox'
import type { Static, TSchema } from '@sinclair/typebox'

export type Payload<Schema extends TSchema | undefined> = Schema extends TSchema
  ? Static<NonNullable<Schema>> extends object
    ? Static<NonNullable<Schema>>
    : JWTPayload
  : JWTPayload;

export interface JWTPayloadSpec {
    iss?: string
    sub?: string
    aud?: string | string[]
    jti?: string
    nbf?: number
    exp?: number
    iat?: number
}

export interface JWTOption<
    Name extends string | undefined = 'jwt',
    Schema extends TSchema | undefined = undefined
> extends JWSHeaderParameters {
    /**
     * Name to decorate method as
     *
     * ---
     * @example
     * For example, `jwt` will decorate Context with `Context.jwt`
     *
     * ```typescript
     * app
     *     .decorate({
     *         name: 'myJWTNamespace',
     *         secret: process.env.JWT_SECRETS
     *     })
     *     .get('/sign/:name', ({ myJWTNamespace, params }) => {
     *         return myJWTNamespace.sign(params)
     *     })
     * ```
     */
    name?: Name
    /**
     * JWT Secret
     */
    secret: string | Uint8Array | KeyLike
    /**
     * Type strict validation for JWT payload
     */
    schema?: Schema
    /**
     * Validate the token and its claims
     */
    verify?: JWTVerifyOptions,

    /**
     * JWT Not Before
     *
     * @see [RFC7519#section-4.1.5](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5)
     */

    nbf?: string | number
    /**
     * JWT Expiration Time
     *
     * @see [RFC7519#section-4.1.4](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4)
     */
    exp?: string | number
}

export const jwt = <
    const Name extends string = 'jwt',
    const Schema extends TSchema | undefined = undefined
>({
    name = 'jwt' as Name,
    secret,
    verify,
    // Start JWT Header
    alg = 'HS256',
    crit,
    schema,
    // End JWT Header
    // Start JWT Payload
    nbf,
    exp,
}: // End JWT Payload
JWTOption<Name, Schema>) => {
    if (!secret) throw new Error("Secret can't be empty")

    const key =
        typeof secret === 'string' ? new TextEncoder().encode(secret) : secret

    const validator = schema
        ? getSchemaValidator(schema, {})
        : undefined

    return new Elysia({
        name: '@elysiajs/jwt',
        seed: {
            name,
            secret,
            verify,
            alg,
            crit,
            schema,
            nbf,
            exp,
        }
    }).decorate(name as Name extends string ? Name : 'jwt', {
        sign: (
          payload: Payload<Schema>,
        ) => {
            let jwt = new SignJWT({
                ...payload,
                nbf: undefined,
                exp: undefined
            }).setProtectedHeader({
                alg,
                crit
            })

            if (nbf) jwt = jwt.setNotBefore(nbf)
            if (exp) jwt = jwt.setExpirationTime(exp)

            return jwt.sign(key)
        },
        verify: async (
            jwt?: string
        ): Promise<Payload<Schema> | false> => {
            if (!jwt) return false

            try {
                const data: any = (await jwtVerify(jwt, key, verify)).payload

                if (validator && !validator!.Check(data))
                    throw new ValidationError('JWT', validator, data)

                return data
            } catch (_) {
                return false
            }
        }
    })
}

export default jwt
