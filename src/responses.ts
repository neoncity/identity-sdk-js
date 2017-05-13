import { ArrayOf, MarshalFrom, MarshalWith } from 'raynor'

import { User } from './entities'
import { UserEvent } from './events'


export class UserResponse {
    @MarshalWith(MarshalFrom(User))
    user: User;
}


export class UserEventsResponse {
    @MarshalWith(ArrayOf(MarshalFrom(UserEvent)))
    events: UserEvent[];
}
