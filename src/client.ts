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
    withAuthInfo(authInfo: AuthInfo): IdentityClient;
    getOrCreateSession(): Promise<[AuthInfo, Session]>;
    getSession(): Promise<Session>;
    expireSession(): Promise<void>;
    getOrCreateUserOnSession(): Promise<[AuthInfo, Session]>;
    getUserOnSession(): Promise<Session>;
}
