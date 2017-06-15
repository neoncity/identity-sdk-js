import * as HttpStatus from 'http-status-codes'
import 'isomorphic-fetch'
import { MarshalFrom, Marshaller } from 'raynor'

import { Env, isLocal } from '@neoncity/common-js'

import { AuthInfo } from './auth-info'
import {
    IdentityClient,
    IdentityError,
    UnauthorizedIdentityError } from './client'
import { Session } from './entities'
import { AuthInfoAndSessionResponse, SessionResponse } from './responses'


export function newIdentityClient(env: Env, identityServiceHost: string): IdentityClient {
    const authInfoMarshaller = new (MarshalFrom(AuthInfo))();
    const authInfoAndSessionResponse = new (MarshalFrom(AuthInfoAndSessionResponse))();
    const sessionResponseMarshaller = new (MarshalFrom(SessionResponse))();

    return new IdentityClientImpl(
	env,
        identityServiceHost,
        authInfoMarshaller,
	authInfoAndSessionResponse,
	sessionResponseMarshaller);
}

class IdentityClientImpl {
    private static readonly _getOrCreateSessionOptions: RequestInit = {
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

    private static readonly _expireSessionOptions: RequestInit = {
	method: 'DELETE',
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

    private static readonly _getUserOnSessionOptions: RequestInit = {
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
    private readonly _authInfoAndSessionResponseMarshaller: Marshaller<AuthInfoAndSessionResponse>;
    private readonly _sessionResponseMarshaller: Marshaller<SessionResponse>;
    private readonly _hasContext: boolean;
    private readonly _authInfo: AuthInfo|null;
    private readonly _origin: string|null;
    private readonly _protocol: string;

    constructor(
	env: Env,
	identityServiceHost: string,
	authInfoMarshaller: Marshaller<AuthInfo>,
	authInfoAndSessionResponseMarshaller: Marshaller<AuthInfoAndSessionResponse>,
	sessionResponseMarshaller: Marshaller<SessionResponse>,
	authInfo: AuthInfo|null = null,
        origin: string|null = null) {
	this._env = env;
	this._identityServiceHost = identityServiceHost;
	this._authInfoMarshaller = authInfoMarshaller;
	this._authInfoAndSessionResponseMarshaller = authInfoAndSessionResponseMarshaller
	this._sessionResponseMarshaller = sessionResponseMarshaller;
        this._hasContext = authInfo != null && origin != null;
	this._authInfo = authInfo;
        this._origin = origin;

	if (isLocal(this._env)) {
	    this._protocol = 'http';
	} else {
	    this._protocol = 'https';
	}
    }

    withContext(authInfo: AuthInfo, origin: string): IdentityClient {
	return new IdentityClientImpl(
	    this._env,
	    this._identityServiceHost,
	    this._authInfoMarshaller,
	    this._authInfoAndSessionResponseMarshaller,
	    this._sessionResponseMarshaller,
	    authInfo,
            origin);
    }
    
    async getOrCreateSession(): Promise<[AuthInfo, Session]> {
	const options = (Object as any).assign({}, IdentityClientImpl._getOrCreateSessionOptions);

	if (this._hasContext) {
	    options.headers = {
                [AuthInfo.HeaderName]: JSON.stringify(this._authInfoMarshaller.pack(this._authInfo as AuthInfo)),
                'Origin': this._origin
            };
	} else if (this._origin != null) {
            // As a special exception when there's no authInfo but an origin header needs to be included,
            // we allow sending it when just origin is not null. This is the only setup when authInfo would be null
            // for a server-side request.
            options.headers = {'Origin': this._origin};
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
		const sessionResponse = this._authInfoAndSessionResponseMarshaller.extract(jsonResponse);
		return [sessionResponse.authInfo, sessionResponse.session];
	    } catch (e) {
		throw new IdentityError(`Could not retrieve session '${e.toString()}'`);
	    }
	} else {
	    throw new IdentityError(`Could not retrieve session - service response ${rawResponse.status}`);
	}
    }
    
    async getSession(): Promise<Session> {
	const options = (Object as any).assign({}, IdentityClientImpl._getSessionOptions);

	if (this._hasContext) {
	    options.headers = {
                [AuthInfo.HeaderName]: JSON.stringify(this._authInfoMarshaller.pack(this._authInfo as AuthInfo)),
                'Origin': this._origin
            };
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

    async expireSession(session: Session): Promise<void> {
	const options = (Object as any).assign({}, IdentityClientImpl._expireSessionOptions);

        options.headers = {[Session.XsrfTokenHeaderName]: session.xsrfToken};

	if (this._hasContext) {
	    options.headers[AuthInfo.HeaderName] = JSON.stringify(this._authInfoMarshaller.pack(this._authInfo as AuthInfo));
            options.headers['Origin'] = this._origin;
	}

	let rawResponse: Response;
	try {
	    rawResponse = await fetch(`${this._protocol}://${this._identityServiceHost}/session`, options);
	} catch (e) {
	    throw new IdentityError(`Could not expire session - request failed because '${e.toString()}'`);
	}

	if (rawResponse.ok) {
	    // Do nothing
	} else {
	    throw new IdentityError(`Could not expire session - service response ${rawResponse.status}`);
	}
    }    

    async getOrCreateUserOnSession(session: Session): Promise<[AuthInfo, Session]> {
	const options = (Object as any).assign({}, IdentityClientImpl._getOrCreateUserOnSessionOptions);

        options.headers = {[Session.XsrfTokenHeaderName]: session.xsrfToken};

	if (this._hasContext) {
	    options.headers[AuthInfo.HeaderName] = JSON.stringify(this._authInfoMarshaller.pack(this._authInfo as AuthInfo));
            options.headers['Origin'] = this._origin;
	}

	let rawResponse: Response;
	try {
	    rawResponse = await fetch(`${this._protocol}://${this._identityServiceHost}/user`, options);
	} catch (e) {
	    throw new IdentityError(`Could not create session - request failed because '${e.toString()}'`);
	}

	if (rawResponse.ok) {
	    try {
		const jsonResponse = await rawResponse.json();
		const sessionResponse = this._authInfoAndSessionResponseMarshaller.extract(jsonResponse);
		return [sessionResponse.authInfo, sessionResponse.session];
	    } catch (e) {
		throw new IdentityError(`Could not retrieve session '${e.toString()}'`);
	    }
	} else if (rawResponse.status == HttpStatus.UNAUTHORIZED) {
	    throw new UnauthorizedIdentityError('User is not authorized');
	} else {
	    throw new IdentityError(`Could not retrieve session - service response ${rawResponse.status}`);
	}
    }
    
    async getUserOnSession(): Promise<Session> {
	const options = (Object as any).assign({}, IdentityClientImpl._getUserOnSessionOptions);

	if (this._hasContext) {
	    options.headers = {
                [AuthInfo.HeaderName]: JSON.stringify(this._authInfoMarshaller.pack(this._authInfo as AuthInfo)),
                'Origin': this._origin
            };
	}

	let rawResponse: Response;
	try {
	    rawResponse = await fetch(`${this._protocol}://${this._identityServiceHost}/user`, options);
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
