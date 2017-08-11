import { ExtractError, MarshalWith, OptionalOf, StringMarshaller, UuidMarshaller } from 'raynor'


export class Auth0AccessTokenMarshaller extends StringMarshaller {
    private static readonly _alnumRegExp: RegExp = new RegExp('^[0-9a-zA-Z_-]+$');

    filter(s: string): string {
        if (s.length == 0) {
            throw new ExtractError('Expected a string to be non-empty');
        }

        if (!Auth0AccessTokenMarshaller._alnumRegExp.test(s)) {
            throw new ExtractError('Should only contain alphanumerics');
        }

        return s;
    }
}


export class Auth0AuthorizationCodeMarshaller extends StringMarshaller {
    private static readonly _alnumRegExp: RegExp = new RegExp('^[0-9a-zA-Z_-]+$');

    filter(s: string): string {
        if (s.length == 0) {
            throw new ExtractError('Expected a string to be non-empty');
        }

        if (!Auth0AuthorizationCodeMarshaller._alnumRegExp.test(s)) {
            throw new ExtractError('Should only contain alphanumerics');
        }

        return s;
    }
}


export class AuthInfo {
    static readonly CookieName = 'neoncity-authinfo';
    static readonly HeaderName = 'X-NeonCity-AuthInfo';

    @MarshalWith(UuidMarshaller)
    sessionId: string;

    @MarshalWith(OptionalOf(Auth0AccessTokenMarshaller))
    auth0AccessToken: string | null;

    constructor(sessionId: string, auth0AccessToken: string | null = null) {
        this.sessionId = sessionId;
        this.auth0AccessToken = auth0AccessToken;
    }
}
