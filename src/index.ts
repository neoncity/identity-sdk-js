import * as m from '@neoncity/common-js/marshall'
import { MarshalWith} from '@neoncity/common-js/marshall'


export enum Role {
    Regular,
    Admin
}


export class User {
    @MarshalWith(m.IdMarshaller)
    id: number;

    @MarshalWith(m.TimeMarshaller)
    timeCreated: Date;

    @MarshalWith(m.TimeMarshaller)
    timeLastUpdated: Date;

    // @MarshalWith(RoleMarshaller)
    role: Role;

    // @MarshalWith(Auth0UserIdHashMarshaller)
    auth0UserIdHash: string;

    isAdmin(): boolean {
        return this.role == Role.Admin;
    }
}
