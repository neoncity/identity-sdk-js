import * as m from '@neoncity/common-js/marshall'
import { ExtractError, MarshalEnum, MarshalFrom, MarshalWith } from '@neoncity/common-js/marshall'


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
