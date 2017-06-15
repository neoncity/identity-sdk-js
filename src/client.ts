import 'isomorphic-fetch'

import { AuthInfo } from './auth-info'
import { Session } from './entities'


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


export interface IdentityClient {
    withContext(authInfo: AuthInfo, origin: string): IdentityClient;
    getOrCreateSession(): Promise<[AuthInfo, Session]>;
    getSession(): Promise<Session>;
    expireSession(session: Session): Promise<void>;
    getOrCreateUserOnSession(session: Session): Promise<[AuthInfo, Session]>;
    getUserOnSession(): Promise<Session>;
}
