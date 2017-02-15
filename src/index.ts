import * as m from '@neoncity/common-js/marshall'
import { MarshalWith } from '@neoncity/common-js/marshall'


export enum Role {
    Unknown = 0,
    Regular = 1,
    Admin = 2
}


export class Auth0UserIdHashMarshaller extends m.StringMarshaller {
    private static readonly _hexRegExp: RegExp = new RegExp('^[0-9a-f]{64}$');

    filter(s: string) {
        if (s.length != 64) {
	    throw new m.ExtractError('Expected string to be 64 characters');
	}

	if (!Auth0UserIdHashMarshaller._hexRegExp.test(s)) {
	    throw new m.ExtractError('Expected all hex characters');
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

    @MarshalWith(m.MarshalEnum(Role))
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
