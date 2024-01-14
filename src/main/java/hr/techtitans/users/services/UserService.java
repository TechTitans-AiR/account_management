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
import org.bson.json.JsonObject;
import org.bson.types.ObjectId;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.crossstore.ChangeSetPersister;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.nio.file.AccessDeniedException;
import java.util.*;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.stream.Collectors;
import java.time.format.DateTimeFormatter;

import org.json.JSONObject;
import org.springframework.web.server.ResponseStatusException;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;


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


    public List<UserDto> allUsers(String token) {
        try {
            if (!isAdmin(token)) {
                throw new AccessDeniedException("Only admin users can access all users");
            }
            List<User> users = userRepository.findAll();
            return users.stream().map(this::mapToUserDto).collect(Collectors.toList());
        } catch (AccessDeniedException e) {
            System.out.println("Access Denied: " + e.getMessage());
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Only admin users can access all users");
        }
    }

    private UserDto mapToUserDto(User user) {
        UserRole userRole = userRoleRepository.findById(user.getUserRole()).orElse(null);
        UserStatus userStatus = userStatusRepository.findById(user.getUserStatus()).orElse(null);


        return new UserDto(
                user.getId(),
                user.getUsername(),
                user.getPassword(),
                user.getPin(),
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

    public ResponseEntity<Object> checkUserRole(String token) {
        try {
            String role = getRoleFromToken(token);
            if (role == null) {
                return new ResponseEntity<>("Invalid token", HttpStatus.UNAUTHORIZED);
            }
            return null;
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseEntity<>("An error occurred while checking user role", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public UserDto getUserById1(String userId, String token){
        ResponseEntity<Object> userRoleCheckResult = checkUserRole(token);
        if (userRoleCheckResult != null) {
            System.out.println("Unauthorized: " + userRoleCheckResult.getBody());
            return null;
        }


        ObjectId objectId = new ObjectId(userId);
        Optional<User> optionalUser = userRepository.findById(objectId);

        if (optionalUser.isPresent()) {
            User user = optionalUser.get();
            return mapToUserDto(user);
        } else {
            return null;
        }

    }


    public ResponseEntity<Object> addUser(Map<String, Object> payload, String token) {
        try {

            if (!isAdmin(token)) {
                return new ResponseEntity<>("Only admin users can add new users", HttpStatus.UNAUTHORIZED);
            }

            System.out.println("Sadržaj payload varijable:");
            payload.forEach((key, value) -> System.out.println(key + ": " + value));
            User user = new User();
            LocalDateTime currentDateTime = LocalDateTime.now();

            String[] fieldsToCheck = {"username", "first_name", "last_name", "email", "password","pin"};
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
            if (userRepository.findByPin((String) payload.get("pin")) != null) {
                throw new UserCreationException("PIN already exists");
            }

            user.setUsername((String) payload.get("username"));
            user.setFirst_name((String) payload.get("first_name"));
            user.setLast_name((String) payload.get("last_name"));
            user.setEmail((String) payload.get("email"));
            user.setDate_created(currentDateTime);
            user.setDate_modified(currentDateTime);
            if (isValid((String) payload.get("address"))) {
                user.setAddress((String) payload.get("address"));
            }
            if (isValid((String) payload.get("phone"))) {
                user.setPhone((String) payload.get("phone"));
            }
            user.setPassword(hashPassword((String) payload.get("password")));
            System.out.println("Password -> " + user.getPassword());
            user.setPin(hashPin((String) payload.get("pin")));
            if (isValid((String) payload.get("date_of_birth"))) {
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

    private boolean isAdmin(String token) {
        try {
            String role = getRoleFromToken(token);
            System.out.println("Role from Token in isAdmin: " + role);

            if (role != null) {
                return "admin".equalsIgnoreCase(role.trim());
            } else {
                System.out.println("Role from Token is null.");
                return false;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }


    public ResponseEntity<Object> updateUser(String userId, Map<String, Object> payload, String token) {
        try {

            if (!isAdmin(token)) {
                return new ResponseEntity<>("Only admin users can update other users", HttpStatus.UNAUTHORIZED);
            }
            ObjectId objectId = new ObjectId(userId);
            Optional<User> optionalUser = userRepository.findById(objectId);

            if (optionalUser.isPresent()) {
                User user = optionalUser.get();
                LocalDateTime currentDateTime = LocalDateTime.now();

                if (isValidField(payload, "username")) {
                    user.setUsername((String) payload.get("username"));
                }
                if (isValidField(payload, "email")) {
                    user.setEmail((String) payload.get("email"));
                }
                if (isValidField(payload, "password")) {
                    user.setPassword(hashPassword((String) payload.get("password")));
                }
                if (isValidField(payload, "pin")) {
                    user.setPin(hashPin((String) payload.get("pin")));
                }
                if (isValidField(payload, "first_name")) {
                    user.setFirst_name((String) payload.get("first_name"));
                }
                if (isValidField(payload, "last_name")) {
                    user.setLast_name((String) payload.get("last_name"));
                }
                if (isValidField(payload, "address")) {
                    user.setAddress((String) payload.get("address"));
                }
                if (isValidField(payload, "phone")) {
                    user.setPhone((String) payload.get("phone"));
                }

                if (isValidField(payload, "date_of_birth")) {
                    String dateOfBirthString = (String) payload.get("date_of_birth");
                    DateTimeFormatter inputFormatter = DateTimeFormatter.ofPattern("dd.MM.yyyy");
                    LocalDate dateOfBirth = LocalDate.parse(dateOfBirthString, inputFormatter);
                    user.setDate_of_birth(dateOfBirth);
                }
                user.setDate_modified(LocalDateTime.now());

                if (payload.containsKey("user_status")) {
                    Object userStatusIdObj = payload.get("user_status");
                    String userStatusId;
                    if (userStatusIdObj instanceof Map) {
                        userStatusId = ((Map<String, String>) userStatusIdObj).get("$oid");
                    } else {
                        userStatusId = (String) userStatusIdObj;
                    }
                    UserStatus userStatus = userStatusRepository.findById(new ObjectId(userStatusId)).orElse(null);
                    if (userStatus != null) {
                        user.setUserStatus(new ObjectId(userStatus.getId().toString()));
                    }
                }

                if (payload.containsKey("user_role")) {
                    Object userRoleIdObj = payload.get("user_role");
                    String userRoleId;
                    if (userRoleIdObj instanceof Map) {
                        userRoleId = ((Map<String, String>) userRoleIdObj).get("$oid");
                    } else {
                        userRoleId = (String) userRoleIdObj;
                    }
                    UserRole userRole = userRoleRepository.findById(new ObjectId(userRoleId)).orElse(null);
                    if (userRole != null) {
                        user.setUserRole(new ObjectId(userRole.getId().toString()));
                    }
                }

                userRepository.save(user);

                return new ResponseEntity<>(HttpStatus.OK);
            } else {
                return new ResponseEntity<>("User not found", HttpStatus.NOT_FOUND);
            }
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseEntity<>("An error occurred", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public ResponseEntity<Object> updateUserInfo(String userId, Map<String, Object> payload, String token) {
        try {
            System.out.println("ZZZZ user id ->"+ userId);
            System.out.println("ZZZZ user id iz tokena"+getUserIdFromToken(token));
            if (!userId.equals(getUserIdFromToken(token))) {
                return new ResponseEntity<>("You can edit only your profile", HttpStatus.UNAUTHORIZED);
            }
            ObjectId objectId = new ObjectId(userId);
            Optional<User> optionalUser = userRepository.findById(objectId);

            if (optionalUser.isPresent()) {
                User user = optionalUser.get();

                if (isValidField(payload, "first_name")) {
                    user.setFirst_name((String) payload.get("first_name"));
                }
                if (isValidField(payload, "last_name")) {
                    user.setLast_name((String) payload.get("last_name"));
                }
                if (isValidField(payload, "address")) {
                    user.setAddress((String) payload.get("address"));
                }
                if (isValidField(payload, "phone")) {
                    user.setPhone((String) payload.get("phone"));
                }

                if (isValidField(payload, "date_of_birth")) {
                    String dateOfBirthString = (String) payload.get("date_of_birth");
                    DateTimeFormatter inputFormatter = DateTimeFormatter.ofPattern("dd.MM.yyyy");
                    LocalDate dateOfBirth = LocalDate.parse(dateOfBirthString, inputFormatter);
                    user.setDate_of_birth(dateOfBirth);
                }
                user.setDate_modified(LocalDateTime.now());
                userRepository.save(user);
                return new ResponseEntity<>(HttpStatus.OK);
            } else {
                return new ResponseEntity<>("User not found", HttpStatus.NOT_FOUND);
            }
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


    public ResponseEntity<Object> deleteUserById(String userId, String token) {
        try {
            if (!isAdmin(token)) {
                return new ResponseEntity<>("Only admin can delete other users", HttpStatus.UNAUTHORIZED);
            }

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

            String username = (String) payload.get("username");
            String password = (String) payload.get("password");

            User user = userRepository.findByUsername(username);

            if (user == null) {
                return new ResponseEntity<>("User not found", HttpStatus.NOT_FOUND);
            }

            if (!checkPassword(password, user.getPassword())) {
                return new ResponseEntity<>("Incorrect password", HttpStatus.UNAUTHORIZED);
            }

            String roleName = userRoleRepository.getRoleNameById(user.getUserRole()).getName();
            System.out.println("User Role from Database: " + roleName);

            String token = generateJwtToken(username, roleName, user.getId());
            if (token != null) {
                System.out.println("TOKEN -> " + token);

                String roleFromToken = getRoleFromToken(token);
                System.out.println("User Role from Token: " + roleFromToken);

                boolean isAdmin = "admin".equalsIgnoreCase(roleFromToken.trim());
                System.out.println("User is an admin: " + isAdmin);

                if (isAdmin) {
                    System.out.println("User is an admin.");
                } else {
                    System.out.println("User is not an admin.");
                }

            } else {
                return new ResponseEntity<>("Cannot create JWT", HttpStatus.INTERNAL_SERVER_ERROR);
            }

            return new ResponseEntity<>(Map.of("message", "Login successful", "token", token), HttpStatus.OK);
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseEntity<>("An error occurred", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public ResponseEntity<Object> loginUserPin(Map<String, Object> payload) {
        try {
            if (!isValidField(payload, "pin")) {
                return new ResponseEntity<>("PIN is required", HttpStatus.BAD_REQUEST);
            }

            String pin = (String) payload.get("pin");


            List<User> usersWithPin = userRepository.findByPinIsNotNull();


            for (User user : usersWithPin) {
                String hashedPinFromDatabase = user.getPin();

                if (checkPin(pin, hashedPinFromDatabase)) {
                    String roleName = userRoleRepository.getRoleNameById(user.getUserRole()).getName();
                    System.out.println("User Role from Database: " + roleName);

                    String token = generateJwtToken(user.getUsername(), roleName, user.getId());
                    if (token != null) {
                        System.out.println("TOKEN -> " + token);

                        String roleFromToken = getRoleFromToken(token);
                        System.out.println("User Role from Token: " + roleFromToken);

                        boolean isAdmin = "admin".equalsIgnoreCase(roleFromToken.trim());
                        System.out.println("User is an admin: " + isAdmin);

                        if (isAdmin) {
                            System.out.println("User is an admin.");
                        } else {
                            System.out.println("User is not an admin.");
                        }

                        return new ResponseEntity<>(Map.of("message", "Login successful", "token", token), HttpStatus.OK);
                    } else {
                        return new ResponseEntity<>("Cannot create JWT", HttpStatus.INTERNAL_SERVER_ERROR);
                    }
                }
            }


            return new ResponseEntity<>("Incorrect PIN", HttpStatus.NOT_FOUND);
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseEntity<>("An error occurred", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }


    public String generateJwtToken(String username, String userRole, String userId) {
        return jwtUtils.generateToken(username, userRole, userId);
    }

    public static String hashPassword(String plainTextPassword) {
        BCrypt.Hasher hasher = BCrypt.withDefaults();
        int cost = 12;
        char[] hashedPasswordChars = hasher.hashToChar(cost, plainTextPassword.toCharArray());
        return new String(hashedPasswordChars);
    }

    public String hashPin(String pin) {
        String pinAsString = String.valueOf(pin);
        BCrypt.Hasher hasher = BCrypt.withDefaults();
        int cost = 12;
        char[] hashedPinChars = hasher.hashToChar(cost, pinAsString.toCharArray());
        return new String(hashedPinChars);
    }




    public static boolean checkPassword(String plainTextPassword, String hashedPassword) {
        BCrypt.Verifyer verifyer = BCrypt.verifyer();
        BCrypt.Result result = verifyer.verify(plainTextPassword.toCharArray(), hashedPassword.toCharArray());
        return result.verified;
    }
    public static boolean checkPin(String plainTextPin, String hashedPin) {
        BCrypt.Verifyer verifyer = BCrypt.verifyer();
        BCrypt.Result result = verifyer.verify(plainTextPin.toCharArray(), hashedPin.toCharArray());
        return result.verified;
    }


    public String getRoleFromToken(String token) {
        try {
            String[] tokenParts = token.split("\\.");

            if (tokenParts.length != 3) {
                System.out.println("Invalid token format");
                System.out.println(tokenParts.length);
                return null;
            }

            String payload = tokenParts[1];

            byte[] decodedPayload = java.util.Base64.getUrlDecoder().decode(payload);
            String decodedPayloadString = new String(decodedPayload, StandardCharsets.UTF_8);

            JSONObject payloadJson = new JSONObject(decodedPayloadString);

            String role = payloadJson.getString("role");

            System.out.println("Role from Token in getRoleFromToken: " + role);
            System.out.println(payloadJson);

            return role;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public String getUserIdFromToken(String token) {
        try {
            String[] tokenParts = token.split("\\.");

            if (tokenParts.length != 3) {
                System.out.println("Invalid token format");
                System.out.println(tokenParts.length);
                return null;
            }

            String payload = tokenParts[1];

            byte[] decodedPayload = java.util.Base64.getUrlDecoder().decode(payload);
            String decodedPayloadString = new String(decodedPayload, StandardCharsets.UTF_8);

            JSONObject payloadJson = new JSONObject(decodedPayloadString);

            String userIdFromToken = payloadJson.getString("userId");

            System.out.println("userIdFromToken from Token: " + userIdFromToken);
            System.out.println(payloadJson);

            return userIdFromToken;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
