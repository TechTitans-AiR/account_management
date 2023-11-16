package hr.techtitans.users.dtos;
import hr.techtitans.users.models.UserRole;
import hr.techtitans.users.models.UserStatus;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import com.fasterxml.jackson.annotation.JsonFormat;
import java.time.LocalDate;
import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserDto {
    private String id;
    private String username;
    private String password;
    private String first_name;
    private String last_name;
    private String email;
    private String address;
    private String phone;
    @JsonFormat(pattern = "dd.MM.yyyy")
    private LocalDate date_of_birth;
    @JsonFormat(pattern = "dd.MM.yyyy HH:mm:ss")
    private LocalDateTime date_created;
    @JsonFormat(pattern = "dd.MM.yyyy HH:mm:ss")
    private LocalDateTime date_modified;

    private UserRole userRole;
    private UserStatus userStatus;
}
