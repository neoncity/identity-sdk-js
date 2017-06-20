import * as r from 'raynor'
import { ExtractError, OptionalOf, MarshalEnum, MarshalFrom, MarshalWith } from 'raynor'

import { LanguageMarshaller } from '@neoncity/common-js'


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


export class XsrfTokenMarshaller extends r.StringMarshaller {
    private static readonly _base64RegExp: RegExp = new RegExp('(?:[A-Za-z0-9+\/]{4})+');

    filter(s: string): string {
        if (s.length != 64) {
            throw new ExtractError('Expected string to be 64 characters');
	}

	if (!XsrfTokenMarshaller._base64RegExp.test(s)) {
	    throw new ExtractError('Expected a base64 string');
	}

	return s;
    }
}


export enum UserState {
    Unknown = 0,
    Active = 1,
    Removed = 2
}


export enum Role {
    Unknown = 0,
    Regular = 1,
    Admin = 2
}


export class User {
    @MarshalWith(r.IdMarshaller)
    id: number;

    @MarshalWith(MarshalEnum(UserState))
    state: UserState;

    @MarshalWith(MarshalEnum(Role))
    role: Role;

    @MarshalWith(r.BooleanMarshaller)
    agreedToCookiePolicy: boolean;    

    @MarshalWith(Auth0UserIdHashMarshaller)
    auth0UserIdHash: string;

    @MarshalWith(r.TimeMarshaller)
    timeCreated: Date;

    @MarshalWith(r.TimeMarshaller)
    timeLastUpdated: Date;

    @MarshalWith(r.StringMarshaller)
    name: string;

    @MarshalWith(r.SecureWebUriMarshaller)
    pictureUri: string;

    @MarshalWith(LanguageMarshaller)
    language: string;

    constructor(id: number, state: UserState, role: Role, agreedToCookiePolicy: boolean, auth0UserIdHash: string, timeCreated: Date, timeLastUpdated: Date, name: string, pictureUri: string, language: string) {
	this.id = id;
        this.state = state;
	this.role = role;
	this.agreedToCookiePolicy = agreedToCookiePolicy;
	this.auth0UserIdHash = auth0UserIdHash;
	this.timeCreated = timeCreated;
	this.timeLastUpdated = timeLastUpdated;
	this.name = name;
	this.pictureUri = pictureUri;
	this.language = language;
    }

    isAdmin(): boolean {
        return this.role == Role.Admin;
    }
}


export enum SessionState {
    // A default value which shouldn't be used.
    Unknown = 0,
    // The session is active and recent activity has been seen for it, but otherwise the user is unknown.
    Active = 1,
    // The session is active and recent activity has been seen for it, and the user is known.
    ActiveAndLinkedWithUser = 2,
    // The session has expired, either of old age or because of a logout.
    Expired = 3,
    // The session has been removed by hand. Either through admin action, or a user with removed their account.
    Removed = 4
}


export class Session {
    static readonly XsrfTokenHeaderName: string = 'X-AuthInfo-XsrfToken';
    
    @MarshalWith(MarshalEnum(SessionState))
    state: SessionState;

    @MarshalWith(XsrfTokenMarshaller)
    xsrfToken: string;

    @MarshalWith(r.TimeMarshaller)
    timeExpires: Date;

    @MarshalWith(r.BooleanMarshaller)
    agreedToCookiePolicy: boolean;

    @MarshalWith(OptionalOf(MarshalFrom(User)))
    user: User|null;

    @MarshalWith(r.TimeMarshaller)
    timeCreated: Date;

    @MarshalWith(r.TimeMarshaller)
    timeLastUpdated: Date;

    hasUser(): boolean {
	return this.state == SessionState.ActiveAndLinkedWithUser && this.user != null /* superflous */;
    }
}
