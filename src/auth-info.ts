import * as r from 'raynor'
import { ExtractError, MarshalWith } from 'raynor'


export class Auth0AccessTokenMarshaller extends r.StringMarshaller {
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


export class Auth0AuthorizationCodeMarshaller extends r.StringMarshaller {
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
    @MarshalWith(Auth0AccessTokenMarshaller)
    auth0AccessToken: string;

    constructor(auth0AccessToken: string) {
	this.auth0AccessToken = auth0AccessToken;
    }
}
