package hr.techtitans.users.services;


import at.favre.lib.crypto.bcrypt.BCrypt;
import hr.techtitans.users.dtos.UserDto;
import hr.techtitans.users.models.User;
import hr.techtitans.users.models.UserRole;
import hr.techtitans.users.models.UserStatus;
import hr.techtitans.users.repositories.UserRepository;
import hr.techtitans.users.repositories.UserRoleRepository;
import hr.techtitans.users.repositories.UserStatusRepository;
import hr.techtitans.users.utils.JWT;
import org.bson.types.ObjectId;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.List;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.Date;
import java.util.Map;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserStatusRepository userStatusRepository;

    @Autowired
    private UserRoleRepository userRoleRepository;

    private JWT jwtUtils;

    @Autowired
    public UserService(JWT jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    public class UserCreationException extends RuntimeException {
        public UserCreationException(String message) {
            super(message);
        }
    }

    public class UserNotFoundException extends RuntimeException {
        public UserNotFoundException(String message) {
            super(message);
        }
    }


    public List<UserDto> allUsers(){
        List<User> users = userRepository.findAll();
        return users.stream().map(this::mapToUserDto).collect(Collectors.toList());
    }

    private UserDto mapToUserDto(User user){
        UserRole userRole = userRoleRepository.findById(user.getUserRole()).orElse(null);
        UserStatus userStatus = userStatusRepository.findById(user.getUserStatus()).orElse(null);
        return new UserDto(
                user.getId(),
                user.getUsername(),
                user.getPassword(),
                user.getFirst_name(),
                user.getLast_name(),
                user.getEmail(),
                user.getAddress(),
                user.getPhone(),
                user.getDate_of_birth(),
                user.getDate_created(),
                user.getDate_modified(),
                userRole,
                userStatus
        );
    }

    public UserDto getUserById(String userId) {
        ObjectId objectId = new ObjectId(userId);
        Optional<User> optionalUser = userRepository.findById(objectId);

        if (optionalUser.isPresent()) {
            User user = optionalUser.get();
            return mapToUserDto(user);
        } else {
            return null;
        }
    }


    public ResponseEntity<Object> addUser(Map<String,Object> payload) {
        try {
            System.out.println("Sadržaj payload varijable:");
            payload.forEach((key, value) -> System.out.println(key + ": " + value));
            User user = new User();
            LocalDateTime currentDateTime = LocalDateTime.now();

            String[] fieldsToCheck = {"username", "first_name", "last_name","email","password"};
            for (String field : fieldsToCheck) {
                if (!isValidField(payload, field)) {
                    throw new UserCreationException(field + " not valid");
                }
            }

            if (userRepository.findByUsername((String) payload.get("username")) != null) {
                throw new UserCreationException("Username already exists");
            }

            if (userRepository.findByEmail((String) payload.get("email")) != null) {
                throw new UserCreationException("Email already exists");
            }

            user.setUsername((String) payload.get("username"));
            user.setFirst_name((String) payload.get("first_name"));
            user.setLast_name((String) payload.get("last_name"));
            user.setEmail((String) payload.get("email"));
            user.setDate_created(currentDateTime);
            user.setDate_modified(currentDateTime);
            if(isValid((String) payload.get("address"))) {
                user.setAddress((String) payload.get("address"));
            }
            if(isValid((String) payload.get("phone"))){
                user.setPhone((String) payload.get("phone"));
            }
            user.setPassword(hashPassword ((String) payload.get("password")));
            System.out.println("Password -> "+user.getPassword());
            if(isValid((String) payload.get("date_of_birth"))){
                String dateOfBirthString = (String) payload.get("date_of_birth");
                LocalDate dateOfBirth = LocalDate.parse(dateOfBirthString);
                user.setDate_of_birth(dateOfBirth);
            }
            String userRoleName = (String) payload.get("user_role");
            UserRole userRole = userRoleRepository.findByName(userRoleName);
            System.out.println("userRole");
            System.out.println(userRole.getId());
            if (userRole != null) {
                user.setUserRole(userRole.getId());
            } else {
                user.setUserRole(null);
            }

            String userStatusName = (String) payload.get("user_status");
            UserStatus userStatus = userStatusRepository.findByName(userStatusName);
            System.out.println("userStatus");
            System.out.println(userStatus.getId());
            if (userStatus != null) {
                user.setUserStatus(userStatus.getId());
            } else {
                user.setUserStatus(null);
            }
            userRepository.insert(user);

            return new ResponseEntity<>("User added successfully", HttpStatus.CREATED);
        } catch (UserCreationException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseEntity<>("An error occurred", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    private boolean isValidField(Map<String, Object> payload, String field) {
        return payload.containsKey(field) && payload.get(field) != null && !payload.get(field).toString().isEmpty();
    }

    private boolean isValid(String fieldValue) {
        return fieldValue != null && !fieldValue.isEmpty();
    }


    public ResponseEntity<Object> deleteUserById(String userId) {
        try {
            if (userId == null || userId.isEmpty()) {
                return new ResponseEntity<>(Map.of("message", "User ID not provided"), HttpStatus.BAD_REQUEST);
            }

            ObjectId objectId = new ObjectId(userId);
            if (userRepository.existsById(objectId)) {
                userRepository.deleteById(objectId);
                Map<String, Object> responseBody = Map.of("message", "User deleted successfully");
                return new ResponseEntity<>(responseBody, HttpStatus.OK);
            } else {
                Map<String, Object> responseBody = Map.of("message", "User not found");
                return new ResponseEntity<>(responseBody, HttpStatus.NOT_FOUND);
            }
        } catch (IllegalArgumentException e) {
            Map<String, Object> responseBody = Map.of("message", "User not found");
            return new ResponseEntity<>(responseBody, HttpStatus.NOT_FOUND);
        } catch (Exception e) {
            e.printStackTrace();
            Map<String, Object> responseBody = Map.of("message", "An error occurred");
            return new ResponseEntity<>(responseBody, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }




    public ResponseEntity<Object> loginUser(Map<String, Object> payload) {
        try {
            if (!isValidField(payload, "username") || !isValidField(payload, "password")) {
                return new ResponseEntity<>("Username and password are required", HttpStatus.BAD_REQUEST);
            }
            System.out.println("UDE");
            String username = (String) payload.get("username");
            String password = (String) payload.get("password");
            System.out.println("UDE"+username);
            User user =  userRepository.findByUsername(username);
            System.out.println("User -> "+user);
            if (user == null) {
                return new ResponseEntity<>("User not found", HttpStatus.NOT_FOUND);
            }

            System.out.println("Provjera passworda -> "+checkPassword(password, user.getPassword()));
            if (!checkPassword(password, user.getPassword())) {
                return new ResponseEntity<>("Incorrect password", HttpStatus.UNAUTHORIZED);
            }
            String roleName = userRoleRepository.getRoleNameById(user.getUserRole()).getName();
            System.out.println("Role Name: " + roleName);
            String token = generateJwtToken(username,roleName);
            if(token != null){
                System.out.println("TOKEN -> "+token);
            }else{
                return new ResponseEntity<>("Cannot create JWT", HttpStatus.INTERNAL_SERVER_ERROR);
            }
            return new ResponseEntity<>(Map.of("message", "Login successful", "token", token), HttpStatus.OK);
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseEntity<>("An error occurred", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public String generateJwtToken(String username, String userRole){
        return jwtUtils.generateToken(username, userRole);
    }

    public static String hashPassword(String plainTextPassword) {
        BCrypt.Hasher hasher = BCrypt.withDefaults();
        int cost = 12;
        char[] hashedPasswordChars = hasher.hashToChar(cost, plainTextPassword.toCharArray());
        return new String(hashedPasswordChars);
    }

    public static boolean checkPassword(String plainTextPassword, String hashedPassword) {
        BCrypt.Verifyer verifyer = BCrypt.verifyer();
        BCrypt.Result result = verifyer.verify(plainTextPassword.toCharArray(), hashedPassword.toCharArray());
        return result.verified;
    }
}
