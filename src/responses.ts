import { ArrayOf, MarshalFrom, MarshalWith } from 'raynor'

import { Session, User } from './entities'
import { UserEvent } from './events'


export class UserResponse {
    @MarshalWith(MarshalFrom(User))
    user: User;
}


export class SessionResponse {
    @MarshalWith(MarshalFrom(Session))
    session: Session;
}


export class UserEventsResponse {
    @MarshalWith(ArrayOf(MarshalFrom(UserEvent)))
    events: UserEvent[];
}
