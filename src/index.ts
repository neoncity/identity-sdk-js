import 'isomorphic-fetch'

import * as m from '@neoncity/common-js/marshall'
import { ExtractError, MarshalEnum, MarshalFrom, MarshalWith, Marshaller } from '@neoncity/common-js/marshall'


export enum Role {
    Unknown = 0,
    Regular = 1,
    Admin = 2
}


export class Auth0UserIdHashMarshaller extends m.StringMarshaller {
    private static readonly _hexRegExp: RegExp = new RegExp('^[0-9a-f]{64}$');

    filter(s: string): string {
        if (s.length != 64) {
	    throw new ExtractError('Expected string to be 64 characters');
	}

	if (!Auth0UserIdHashMarshaller._hexRegExp.test(s)) {
	    throw new ExtractError('Expected all hex characters');
	}

	return s;
    }
}



export class User {
    @MarshalWith(m.IdMarshaller)
    id: number;

    @MarshalWith(m.TimeMarshaller)
    timeCreated: Date;

    @MarshalWith(m.TimeMarshaller)
    timeLastUpdated: Date;

    @MarshalWith(MarshalEnum(Role))
    role: Role;

    @MarshalWith(Auth0UserIdHashMarshaller)
    auth0UserIdHash: string;

    @MarshalWith(m.UriMarshaller)
    pictureUri: string;

    constructor(id: number, timeCreated: Date, timeLastUpdated: Date, role: Role, auth0UserIdHash: string, pictureUri: string) {
	this.id = id;
	this.timeCreated = timeCreated;
	this.timeLastUpdated = timeLastUpdated;
	this.role = role;
	this.auth0UserIdHash = auth0UserIdHash;
	this.pictureUri = pictureUri;
    }

    isAdmin(): boolean {
        return this.role == Role.Admin;
    }
}


export class Auth0AccessTokenMarshaller extends m.StringMarshaller {
    private static readonly _alnumRegExp: RegExp = new RegExp('^[0-9a-zA-Z]+$');
    
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


export class AuthInfo {
    @MarshalWith(Auth0AccessTokenMarshaller)
    auth0AccessToken: string;

    constructor(auth0AccessToken: string) {
	this.auth0AccessToken = auth0AccessToken;
    }
}


export class IdentityResponse {
    @MarshalWith(MarshalFrom(User))
    user: User;
}


export class IdentityError extends Error {
    constructor(message: string) {
	super(message);
	this.name = 'IdentityError';
    }
}


export function newIdentityService(auth0AccessToken: string, identityServiceHost: string) {
    const authInfoMarshaller = new (MarshalFrom(AuthInfo))();
    const identityResponseMarshaller = new (MarshalFrom(IdentityResponse))();

    return new IdentityService(auth0AccessToken, identityServiceHost, authInfoMarshaller, identityResponseMarshaller);
}


export class IdentityService {
    private static readonly _getUserOptions: RequestInit = {
	method: 'GET',
	mode: 'cors',
	cache: 'no-cache',
	redirect: 'error',
	referrer: 'client'
    };

    private static readonly _createUserOptions: RequestInit = {
	method: 'POST',
	mode: 'cors',
	cache: 'no-cache',
	redirect: 'error',
	referrer: 'client'
    };
    
    private readonly _auth0AccessToken: string;
    private readonly _identityServiceHost: string;
    private readonly _authInfoMarshaller: Marshaller<AuthInfo>;
    private readonly _identityResponseMarshaller: Marshaller<IdentityResponse>;

    constructor(
	auth0AccessToken: string,
	identityServiceHost: string,
	authInfoMarshaller: Marshaller<AuthInfo>,
	identityResponseMarshaller: Marshaller<IdentityResponse>) {
	this._auth0AccessToken = auth0AccessToken;
	this._identityServiceHost = identityServiceHost;
	this._authInfoMarshaller = authInfoMarshaller;
	this._identityResponseMarshaller = identityResponseMarshaller;
    }

    async getOrCreateUser(): Promise<User> {
	const authInfo = new AuthInfo(this._auth0AccessToken);
	const authInfoSerialized = JSON.stringify(this._authInfoMarshaller.pack(authInfo));
	const options = (Object as any).assign({}, IdentityService._getUserOptions, {headers: {'X-NeonCity-AuthInfo': authInfoSerialized}});

	let rawResponse: Response;
	try {
	    rawResponse = await fetch(`http://${this._identityServiceHost}/user`, options);
	} catch (e) {
	    throw new IdentityError(`Could not retrieve user - request failed because '${e.toString()}'`);
	}

	if (rawResponse.ok) {
	    try {
		const jsonResponse = await rawResponse.json();
		const identityResponse = this._identityResponseMarshaller.extract(jsonResponse);
		return identityResponse.user;
	    } catch (e) {
		throw new IdentityError(`Could not retrieve user '${e.toString()}'`);
	    }
	} else if (rawResponse.status == 404) {
	    return await this._createUser();
	} else {
	    throw new IdentityError(`Could not retrieve user - service response ${rawResponse.status}`);
	}
    }

    private async _createUser(): Promise<User> {
	const authInfo = new AuthInfo(this._auth0AccessToken);
	const authInfoSerialized = JSON.stringify(this._authInfoMarshaller.pack(authInfo));
	const options = (Object as any).assign({}, IdentityService._createUserOptions, {headers: {'X-NeonCity-AuthInfo': authInfoSerialized}});

	let rawResponse: Response;
	try {
	    rawResponse = await fetch(`http://${this._identityServiceHost}/user`, options);
	} catch (e) {
	    throw new IdentityError(`Could not create user - request failed because '${e.toString()}'`);
	}

	if (rawResponse.ok) {
	    try {
		const jsonResponse = await rawResponse.json();
		const identityResponse = this._identityResponseMarshaller.extract(jsonResponse);
		return identityResponse.user;
	    } catch (e) {
		throw new IdentityError(`Could not create user '${e.toString()}'`);
	    }
	} else {
	    throw new IdentityError(`Could not create user - service response ${rawResponse.status}`);
	}
    }
}


// async function main(): Promise<number> {
//     const authInfoMarshaller = new (MarshalFrom(AuthInfo))();
//     const identityResponseMarshaller = new (MarshalFrom(IdentityResponse))();
//     const identityService = new IdentityService('chop-suei', 'localhost:10001', authInfoMarshaller, identityResponseMarshaller);

//     try {
// 	const user = await identityService.getOrCreateUser();

// 	console.log(user);
//     } catch (e) {
// 	console.log(e);
//     }

//     return 10;
// }

// console.log('here');
// main().then(() => { console.log('Hello'); });
