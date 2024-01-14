package hr.techtitans.users.models;

import hr.techtitans.users.repositories.UserRoleRepository;
import hr.techtitans.users.repositories.UserStatusRepository;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.bson.types.ObjectId;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Document(collection = "users")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class User {
    @Id
    private String id;

    @Field(name = "user_status")
    private ObjectId userStatus;

    @Field(name = "user_role")
    private ObjectId userRole;

    private String username;

    private String password;

    private String pin;

    private String first_name;

    private String last_name;

    private String email;

    private LocalDateTime date_created;

    private LocalDateTime date_modified;

    private String address;

    private String phone;

    private LocalDate date_of_birth;

    public UserRole getUserRole(UserRoleRepository userRoleRepository) {
        return userRoleRepository.findById(userRole).orElse(null);
    }

    public UserStatus getUserStatus(UserStatusRepository userStatusRepository) {
        return userStatusRepository.findById(userStatus).orElse(null);
    }
}
