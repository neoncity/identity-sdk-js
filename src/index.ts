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


export class CreateUserRequest {
    @MarshalWith(Auth0AccessTokenMarshaller)
    auth0AccessToken: string;
}


export class GetUserRequest {
    @MarshalWith(Auth0AccessTokenMarshaller)
    auth0AccessToken: string;
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


export class IdentityService {
    private static readonly _getUserOptions: RequestInit = {
	method: 'GET',
	mode: 'cors',
	cache: 'no-cache',
	redirect: 'error',
	referrer: 'client'
    };

    private static readonly _createUserOptions: RequestInit = {
	method: 'GET',
	mode: 'cors',
	cache: 'no-cache',
	redirect: 'error',
	referrer: 'client'
    };
    
    private readonly _auth0AccessToken: string;
    private readonly _identityServiceHost: string;
    private readonly _identityResponseMarshaller: Marshaller<IdentityResponse>;

    constructor(auth0AccessToken: string, identityServiceHost: string, identityResponseMarshaller: Marshaller<IdentityResponse>) {
	this._auth0AccessToken = auth0AccessToken;
	this._identityServiceHost = identityServiceHost;
	this._identityResponseMarshaller = identityResponseMarshaller;
    }

    async getOrCreateUser(): Promise<User> {
	const getUserRequest = new GetUserRequest();
	getUserRequest.auth0AccessToken = this._auth0AccessToken;

	let rawResponse: Response;
	try {
	    rawResponse = await fetch("http://${this._identityServiceDomain}/user", IdentityService._getUserOptions);
	} catch (e) {
	    throw new IdentityError("Could not retrieve user - request failed because '${e.toString()}'");
	}

	if (rawResponse.ok) {
	    try {
		const jsonResponse = await rawResponse.json();
		const identityResponse = this._identityResponseMarshaller.extract(jsonResponse);
		return identityResponse.user;
	    } catch (e) {
		if (e instanceof ExtractError) {
		    throw new IdentityError("Could not retrieve user - marshal error '${e.toString()}'");
		} else {
		    throw new IdentityError('Could not retrieve user - JSON serialization error');
		}
	    }
	} else if (rawResponse.status == 404) {
	    return await this._createUser();
	} else {
	    throw new IdentityError("Could not retrieve user - service response ${rawResponse.status}");
	}
    }

    private async _createUser(): Promise<User> {
	const createUserRequest = new CreateUserRequest();
	createUserRequest.auth0AccessToken = this._auth0AccessToken;

	let rawResponse: Response;
	try {
	    rawResponse = await fetch("http://${this._identityServiceDomain}/user", IdentityService._createUserOptions);
	} catch (e) {
	    throw new IdentityError("Could not create user - request failed because '${e.toString()}'");
	}

	if (rawResponse.ok) {
	    try {
		const jsonResponse = await rawResponse.json();
		const identityResponse = this._identityResponseMarshaller.extract(jsonResponse);
		return identityResponse.user;
	    } catch (e) {
		if (e instanceof ExtractError) {
		    throw new IdentityError("Could not create user - marshal error '${e.toString()}'");
		} else {
		    throw new IdentityError('Could not retrieve user - JSON serialization error');
		}
	    }
	} else {
	    throw new IdentityError("Could not create user - service response ${rawResponse.status}");
	}
    }
}
