import * as HttpStatus from 'http-status-codes'
import 'isomorphic-fetch'
import * as r from 'raynor'
import { ExtractError, MarshalEnum, MarshalFrom, MarshalWith, Marshaller } from 'raynor'


export enum Role {
    Unknown = 0,
    Regular = 1,
    Admin = 2
}


export enum UserEventType {
    Unknown = 0,
    Created = 1,
    Removed = 2
}


export class Auth0UserIdHashMarshaller extends r.StringMarshaller {
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


export class UserEvent {
    @MarshalWith(r.IdMarshaller)
    id: number;
    
    @MarshalWith(MarshalEnum(UserEventType))
    type: UserEventType;

    @MarshalWith(r.TimeMarshaller)
    timestamp: Date;

    @MarshalWith(r.NullMarshaller)
    data: null;
}


export class User {
    @MarshalWith(r.IdMarshaller)
    id: number;

    @MarshalWith(r.TimeMarshaller)
    timeCreated: Date;

    @MarshalWith(r.TimeMarshaller)
    timeLastUpdated: Date;

    @MarshalWith(MarshalEnum(Role))
    role: Role;

    @MarshalWith(Auth0UserIdHashMarshaller)
    auth0UserIdHash: string;

    @MarshalWith(r.StringMarshaller)
    name: string;

    @MarshalWith(r.UriMarshaller)
    pictureUri: string;

    constructor(id: number, timeCreated: Date, timeLastUpdated: Date, role: Role, auth0UserIdHash: string, name: string, pictureUri: string) {
	this.id = id;
	this.timeCreated = timeCreated;
	this.timeLastUpdated = timeLastUpdated;
	this.role = role;
	this.auth0UserIdHash = auth0UserIdHash;
	this.name = name;
	this.pictureUri = pictureUri;
    }

    isAdmin(): boolean {
        return this.role == Role.Admin;
    }
}


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


export class UnauthorizedIdentityError extends IdentityError {
    constructor(message: string) {
	super(message);
	this.name = 'UnauthorizedIdentityError';
    }
}


export function newIdentityClient(identityServiceHost: string) {
    const authInfoMarshaller = new (MarshalFrom(AuthInfo))();
    const identityResponseMarshaller = new (MarshalFrom(IdentityResponse))();

    return new IdentityClient(identityServiceHost, authInfoMarshaller, identityResponseMarshaller);
}


export class IdentityClient {
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
    
    private readonly _identityServiceHost: string;
    private readonly _authInfoMarshaller: Marshaller<AuthInfo>;
    private readonly _identityResponseMarshaller: Marshaller<IdentityResponse>;

    constructor(
	identityServiceHost: string,
	authInfoMarshaller: Marshaller<AuthInfo>,
	identityResponseMarshaller: Marshaller<IdentityResponse>) {
	this._identityServiceHost = identityServiceHost;
	this._authInfoMarshaller = authInfoMarshaller;
	this._identityResponseMarshaller = identityResponseMarshaller;
    }

    async getUser(accessToken: string): Promise<User> {
	const authInfo = new AuthInfo(accessToken);
	
	const options = (Object as any).assign({}, IdentityClient._getUserOptions, {
	    headers: {'X-NeonCity-AuthInfo': JSON.stringify(this._authInfoMarshaller.pack(authInfo))}
	});

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
	} else if (rawResponse.status == HttpStatus.UNAUTHORIZED) {
	    throw new UnauthorizedIdentityError('User is not authorized');
	} else {
	    throw new IdentityError(`Could not retrieve user - service response ${rawResponse.status}`);
	}    
    }

    async getOrCreateUser(accessToken: string): Promise<User> {
	const authInfo = new AuthInfo(accessToken);
	
	const options = (Object as any).assign({}, IdentityClient._getUserOptions, {
	    headers: {'X-NeonCity-AuthInfo': JSON.stringify(this._authInfoMarshaller.pack(authInfo))}
	});

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
	} else if (rawResponse.status == HttpStatus.NOT_FOUND) {
	    return await this._createUser(accessToken);
	} else if (rawResponse.status == HttpStatus.UNAUTHORIZED) {
	    throw new UnauthorizedIdentityError('User is not authorized');
	} else {
	    throw new IdentityError(`Could not retrieve user - service response ${rawResponse.status}`);
	}
    }

    private async _createUser(accessToken: string): Promise<User> {
	const authInfo = new AuthInfo(accessToken);

	const options = (Object as any).assign({}, IdentityClient._createUserOptions, {
	    headers: {'X-NeonCity-AuthInfo': JSON.stringify(this._authInfoMarshaller.pack(authInfo))}
	});

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
