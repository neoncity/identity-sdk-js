import * as HttpStatus from 'http-status-codes'
import 'isomorphic-fetch'
import * as r from 'raynor'
import { ArrayOf, ExtractError, MarshalEnum, MarshalFrom, MarshalWith, Marshaller } from 'raynor'

import { Env, isLocal } from '@neoncity/common-js/env'


export enum UserState {
    Unknown = 0,
    Anonymous = 1,
    ActiveAndLinkedWithAuth0 = 2,
    Removed = 3
}


export enum Role {
    Unknown = 0,
    Regular = 1,
    Admin = 2
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


export enum UserEventType {
    Unknown = 0,
    Created = 1,
    Recreated = 2,
    Removed = 3
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

    @MarshalWith(MarshalEnum(UserState))
    state: UserState;

    @MarshalWith(MarshalEnum(Role))
    role: Role;

    @MarshalWith(Auth0UserIdHashMarshaller)
    auth0UserIdHash: string;

    @MarshalWith(r.TimeMarshaller)
    timeCreated: Date;

    @MarshalWith(r.TimeMarshaller)
    timeLastUpdated: Date;

    @MarshalWith(r.StringMarshaller)
    name: string;

    @MarshalWith(r.UriMarshaller)
    pictureUri: string;

    constructor(id: number, state: UserState, role: Role, auth0UserIdHash: string, timeCreated: Date, timeLastUpdated: Date, name: string, pictureUri: string) {
	this.id = id;
        this.state = state;
	this.role = role;
	this.auth0UserIdHash = auth0UserIdHash;
	this.timeCreated = timeCreated;
	this.timeLastUpdated = timeLastUpdated;
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


export class UserResponse {
    @MarshalWith(MarshalFrom(User))
    user: User;
}


export class UserEventsResponse {
    @MarshalWith(ArrayOf(MarshalFrom(UserEvent)))
    events: UserEvent[];
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


export function newIdentityClient(env: Env, identityServiceHost: string) {
    const authInfoMarshaller = new (MarshalFrom(AuthInfo))();
    const userResponseMarshaller = new (MarshalFrom(UserResponse))();
    const userEventsResponseMarshaller = new (MarshalFrom(UserEventsResponse))()

    return new IdentityClient(
	env,
        identityServiceHost,
        authInfoMarshaller,
        userResponseMarshaller,
        userEventsResponseMarshaller);
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

    private static readonly _getUserEventsOptions: RequestInit = {
	method: 'GET',
	mode: 'cors',
	cache: 'no-cache',
	redirect: 'error',
	referrer: 'client'
    };

    private readonly _env: Env;
    private readonly _identityServiceHost: string;
    private readonly _authInfoMarshaller: Marshaller<AuthInfo>;
    private readonly _userResponseMarshaller: Marshaller<UserResponse>;
    private readonly _userEventsResponseMarshaller: Marshaller<UserEventsResponse>;
    private readonly _protocol: string;

    constructor(
	env: Env,
	identityServiceHost: string,
	authInfoMarshaller: Marshaller<AuthInfo>,
	userResponseMarshaller: Marshaller<UserResponse>,
        userEventsResponseMarshaller: Marshaller<UserEventsResponse>) {
	this._env = env;
	this._identityServiceHost = identityServiceHost;
	this._authInfoMarshaller = authInfoMarshaller;
	this._userResponseMarshaller = userResponseMarshaller;
	this._userEventsResponseMarshaller = userEventsResponseMarshaller;

	if (isLocal(this._env)) {
	    this._protocol = 'http';
	} else {
	    this._protocol = 'https';
	}
    }

    async getUser(accessToken: string): Promise<User> {
	const authInfo = new AuthInfo(accessToken);
	
	const options = (Object as any).assign({}, IdentityClient._getUserOptions, {
	    headers: {'X-NeonCity-AuthInfo': JSON.stringify(this._authInfoMarshaller.pack(authInfo))}
	});

	let rawResponse: Response;
	try {
	    rawResponse = await fetch(`${this._protocol}://${this._identityServiceHost}/user`, options);
	} catch (e) {
	    throw new IdentityError(`Could not retrieve user - request failed because '${e.toString()}'`);
	}

	if (rawResponse.ok) {
	    try {
		const jsonResponse = await rawResponse.json();
		const userResponse = this._userResponseMarshaller.extract(jsonResponse);
		return userResponse.user;
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
	    rawResponse = await fetch(`${this._protocol}://${this._identityServiceHost}/user`, options);
	} catch (e) {
	    throw new IdentityError(`Could not retrieve user - request failed because '${e.toString()}'`);
	}

	if (rawResponse.ok) {
	    try {
		const jsonResponse = await rawResponse.json();
		const userResponse = this._userResponseMarshaller.extract(jsonResponse);
		return userResponse.user;
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


    async getUserEvents(accessToken: string): Promise<UserEvent[]> {
	const authInfo = new AuthInfo(accessToken);
	
	const options = (Object as any).assign({}, IdentityClient._getUserEventsOptions, {
	    headers: {'X-NeonCity-AuthInfo': JSON.stringify(this._authInfoMarshaller.pack(authInfo))}
	});

	let rawResponse: Response;
	try {
	    rawResponse = await fetch(`${this._protocol}://${this._identityServiceHost}/user/events`, options);
	} catch (e) {
	    throw new IdentityError(`Could not retrieve user eventss - request failed because '${e.toString()}'`);
	}

	if (rawResponse.ok) {
	    try {
		const jsonResponse = await rawResponse.json();
		const userEventsResponse = this._userEventsResponseMarshaller.extract(jsonResponse);
		return userEventsResponse.events;
	    } catch (e) {
		throw new IdentityError(`Could not retrieve user events '${e.toString()}'`);
	    }
	} else if (rawResponse.status == HttpStatus.UNAUTHORIZED) {
	    throw new UnauthorizedIdentityError('User is not authorized');
	} else {
	    throw new IdentityError(`Could not retrieve user events - service response ${rawResponse.status}`);
	}
    }
    

    private async _createUser(accessToken: string): Promise<User> {
	const authInfo = new AuthInfo(accessToken);

	const options = (Object as any).assign({}, IdentityClient._createUserOptions, {
	    headers: {'X-NeonCity-AuthInfo': JSON.stringify(this._authInfoMarshaller.pack(authInfo))}
	});

	let rawResponse: Response;
	try {
	    rawResponse = await fetch(`${this._protocol}://${this._identityServiceHost}/user`, options);
	} catch (e) {
	    throw new IdentityError(`Could not create user - request failed because '${e.toString()}'`);
	}

	if (rawResponse.ok) {
	    try {
		const jsonResponse = await rawResponse.json();
		const userResponse = this._userResponseMarshaller.extract(jsonResponse);
		return userResponse.user;
	    } catch (e) {
		throw new IdentityError(`Could not create user '${e.toString()}'`);
	    }
	} else {
	    throw new IdentityError(`Could not create user - service response ${rawResponse.status}`);
	}
    }
}
