import * as HttpStatus from 'http-status-codes'
import 'isomorphic-fetch'
import { MarshalFrom, Marshaller } from 'raynor'

import { Env, isLocal } from '@neoncity/common-js'

import { AuthInfo } from './auth-info'
import { Session } from './entities'
import { SessionResponse } from './responses'


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

    return new IdentityClient(
	env,
        identityServiceHost,
        authInfoMarshaller,
	sessionResponseMarshaller);
}


export class IdentityClient {
    private static readonly _getOrCreateSessionOptions: RequestInit = {
	method: 'POST',
	mode: 'cors',
	cache: 'no-cache',
	redirect: 'error',
	referrer: 'client',
	credentials: 'include'
    };

    private static readonly _getOrCreateUserOnSessionOptions: RequestInit = {
	method: 'POST',
	mode: 'cors',
	cache: 'no-cache',
	redirect: 'error',
	referrer: 'client',
	credentials: 'include'
    };

    private static readonly _getSessionOptions: RequestInit = {
	method: 'GET',
	mode: 'cors',
	cache: 'no-cache',
	redirect: 'error',
	referrer: 'client',
	credentials: 'include'
    };

    private readonly _env: Env;
    private readonly _identityServiceHost: string;
    private readonly _authInfoMarshaller: Marshaller<AuthInfo>;
    private readonly _sessionResponseMarshaller: Marshaller<SessionResponse>;
    private readonly _authInfo: AuthInfo|null;
    private readonly _protocol: string;

    constructor(
	env: Env,
	identityServiceHost: string,
	authInfoMarshaller: Marshaller<AuthInfo>,
	sessionResponseMarshaller: Marshaller<SessionResponse>,
	authInfo: AuthInfo|null = null) {
	this._env = env;
	this._identityServiceHost = identityServiceHost;
	this._authInfoMarshaller = authInfoMarshaller;
	this._sessionResponseMarshaller = sessionResponseMarshaller;
	this._authInfo = authInfo;

	if (isLocal(this._env)) {
	    this._protocol = 'http';
	} else {
	    this._protocol = 'https';
	}
    }

    withAuthInfo(authInfo: AuthInfo): IdentityClient {
	return new IdentityClient(
	    this._env,
	    this._identityServiceHost,
	    this._authInfoMarshaller,
	    this._sessionResponseMarshaller,
	    authInfo);
    }
    
    async getOrCreateSession(): Promise<Session> {
	const options = (Object as any).assign({}, IdentityClient._getOrCreateSessionOptions);

	if (this._authInfo != null) {
	    options.headers = {[AuthInfo.HeaderName]: JSON.stringify(this._authInfoMarshaller.pack(this._authInfo))};
	}

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
    
    async getOrCreateUserOnSession(): Promise<Session> {
	const options = (Object as any).assign({}, IdentityClient._getOrCreateUserOnSessionOptions);

	if (this._authInfo != null) {
	    options.headers = {[AuthInfo.HeaderName]: JSON.stringify(this._authInfoMarshaller.pack(this._authInfo))};
	}

	let rawResponse: Response;
	try {
	    rawResponse = await fetch(`${this._protocol}://${this._identityServiceHost}/session/user`, options);
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
	} else if (rawResponse.status == HttpStatus.UNAUTHORIZED) {
	    throw new UnauthorizedIdentityError('User is not authorized');
	} else {
	    throw new IdentityError(`Could not retrieve session - service response ${rawResponse.status}`);
	}
    }
    
    async getSession(): Promise<Session> {
	const options = (Object as any).assign({}, IdentityClient._getSessionOptions);

	if (this._authInfo != null) {
	    options.headers = {[AuthInfo.HeaderName]: JSON.stringify(this._authInfoMarshaller.pack(this._authInfo))};
	}

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
	} else if (rawResponse.status == HttpStatus.UNAUTHORIZED) {
	    throw new UnauthorizedIdentityError('User is not authorized');
	} else {
	    throw new IdentityError(`Could not retrieve session - service response ${rawResponse.status}`);
	}
    }
}
