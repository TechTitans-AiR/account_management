package hr.techtitans.users.repositories;

import hr.techtitans.users.models.UserStatus;
import org.bson.types.ObjectId;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserStatusRepository extends MongoRepository<UserStatus, ObjectId> {
    UserStatus findByName(String name);
}
