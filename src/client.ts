import * as HttpStatus from 'http-status-codes'
import 'isomorphic-fetch'
import { MarshalFrom, Marshaller } from 'raynor'

import { Env, isLocal } from '@neoncity/common-js'

import { AuthInfo } from './auth-info'
import { Session, User } from './entities'
import { UserEvent } from './events'
import { SessionResponse, UserResponse, UserEventsResponse } from './responses'


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
    const sessionResponseMarshaller = new (MarshalFrom(SessionResponse))();
    const userResponseMarshaller = new (MarshalFrom(UserResponse))();
    const userEventsResponseMarshaller = new (MarshalFrom(UserEventsResponse))()

    return new IdentityClient(
	env,
        identityServiceHost,
        authInfoMarshaller,
	sessionResponseMarshaller,
        userResponseMarshaller,
        userEventsResponseMarshaller);
}


export class IdentityClient {
    private static readonly _createSessionOptions: RequestInit = {
	method: 'POST',
	mode: 'cors',
	cache: 'no-cache',
	redirect: 'error',
	referrer: 'client'
    };

    private static readonly _getSessionOptions: RequestInit = {
	method: 'GET',
	mode: 'cors',
	cache: 'no-cache',
	redirect: 'error',
	referrer: 'client'
    };
    
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
    private readonly _sessionResponseMarshaller: Marshaller<SessionResponse>;
    private readonly _userResponseMarshaller: Marshaller<UserResponse>;
    private readonly _userEventsResponseMarshaller: Marshaller<UserEventsResponse>;
    private readonly _protocol: string;

    constructor(
	env: Env,
	identityServiceHost: string,
	authInfoMarshaller: Marshaller<AuthInfo>,
	sessionResponseMarshaller: Marshaller<SessionResponse>,
	userResponseMarshaller: Marshaller<UserResponse>,
        userEventsResponseMarshaller: Marshaller<UserEventsResponse>) {
	this._env = env;
	this._identityServiceHost = identityServiceHost;
	this._authInfoMarshaller = authInfoMarshaller;
	this._sessionResponseMarshaller = sessionResponseMarshaller;
	this._userResponseMarshaller = userResponseMarshaller;
	this._userEventsResponseMarshaller = userEventsResponseMarshaller;

	if (isLocal(this._env)) {
	    this._protocol = 'http';
	} else {
	    this._protocol = 'https';
	}
    }

    async createSession(): Promise<Session> {
	const options = IdentityClient._createSessionOptions;

	let rawResponse: Response;
	try {
	    rawResponse = await fetch(`${this._protocol}://${this._identityServiceHost}/session`, options);
	} catch (e) {
	    throw new IdentityError(`Could not create session - request failed because '${e.toString()}'`);
	}

	if (rawResponse.ok) {
	    try {
		const jsonResponse = await rawResponse.json();
		const sessionResponse = this._sessionResponseMarshaller.extract(jsonResponse);
		return sessionResponse.session;
	    } catch (e) {
		throw new IdentityError(`Could not retrieve session '${e.toString()}'`);
	    }
	} else {
	    throw new IdentityError(`Could not retrieve session - service response ${rawResponse.status}`);
	}	    
    }

    async getOrCreateSession(sessionId: string): Promise<Session> {
	const options = IdentityClient._getSessionOptions;

	let rawResponse: Response;
	try {
	    rawResponse = await fetch(`${this._protocol}://${this._identityServiceHost}/session/${sessionId}`, options);
	} catch (e) {
	    throw new IdentityError(`Could not retrieve session - request failed because '${e.toString()}'`);
	}

	if (rawResponse.ok) {
	    try {
		const jsonResponse = await rawResponse.json();
		const sessionResponse = this._sessionResponseMarshaller.extract(jsonResponse);
		return sessionResponse.session;
	    } catch (e) {
		throw new IdentityError(`Could not retrieve session '${e.toString()}'`);
	    }
	} else if (rawResponse.status == HttpStatus.NOT_FOUND) {
	    return await this.createSession();
	} else {
	    throw new IdentityError(`Could not retrieve session - service response ${rawResponse.status}`);
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

    async getUserEvents(accessToken: string): Promise<UserEvent[]> {
	const authInfo = new AuthInfo(accessToken);
	
	const options = (Object as any).assign({}, IdentityClient._getUserEventsOptions, {
	    headers: {'X-NeonCity-AuthInfo': JSON.stringify(this._authInfoMarshaller.pack(authInfo))}
	});

	let rawResponse: Response;
	try {
	    rawResponse = await fetch(`${this._protocol}://${this._identityServiceHost}/user/event`, options);
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
