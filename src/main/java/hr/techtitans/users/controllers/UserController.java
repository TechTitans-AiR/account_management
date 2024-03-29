package hr.techtitans.users.controllers;

import hr.techtitans.users.dtos.UserDto;
import hr.techtitans.users.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.nio.file.AccessDeniedException;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/users")
public class UserController {

    @Autowired
    private UserService userService;

    @GetMapping
    public ResponseEntity<List<UserDto>> getAllUsers(@RequestHeader("Authorization") String token) {
        return new ResponseEntity<List<UserDto>>(userService.allUsers(token), HttpStatus.OK);
    }

/*
    @GetMapping("/{userId}")
    public ResponseEntity<?> getUserById(@PathVariable String userId, @RequestHeader("Authorization") String token) {
        try {
            UserDto userDto = userService.getUserById1(userId, token);

            if (userDto != null) {
                return new ResponseEntity<>(userDto, HttpStatus.OK);
            } else {
                String errorMessage = "User with id: " + userId + " is not found.";
                return new ResponseEntity<>(errorMessage, HttpStatus.NOT_FOUND);
            }
        } catch (AccessDeniedException ex) {
            if (ex.getMessage().contains("Merchants can only retrieve their own information.")) {
                return new ResponseEntity<>("Access denied. Merchants can only retrieve their own information.", HttpStatus.FORBIDDEN);
            } else {
                return new ResponseEntity<>("Access denied. Only admins can retrieve user information.", HttpStatus.FORBIDDEN);
            }
        } catch (Exception ex) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
*/
@GetMapping("/{userId}")
public ResponseEntity<?> getUserById(@PathVariable String userId, @RequestHeader("Authorization") String token){
    try {
        ResponseEntity<Object> userCheckResult = userService.checkUserRole(token);
        if (userCheckResult != null) {
            return userCheckResult;
        }
        UserDto userDto = userService.getUserById1(userId, token);

        if (userDto != null) {
            return new ResponseEntity<>(userDto, HttpStatus.OK);
        } else {
            String errorMessage = "User with id: " + userId + " is not found.";
            return new ResponseEntity<>(errorMessage, HttpStatus.NOT_FOUND);
        }
    } catch (Exception ex) {

        return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
    @PostMapping("/create")
    public ResponseEntity<Object> addUser(@RequestBody Map<String, Object> payload, @RequestHeader("Authorization") String token) {
        try {
            return userService.addUser(payload, token);
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseEntity<>("An error occurred", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }


    @PutMapping("/update/{userId}")
    public ResponseEntity<Object> updateUser(@PathVariable String userId, @RequestBody Map<String, Object> payload, @RequestHeader("Authorization") String token) {
        try {
            ResponseEntity<Object> response = userService.updateUser(userId, payload, token);

            if (response.getStatusCode() == HttpStatus.OK) {
                UserDto updatedUserDto = userService.getUserById(userId);
                return new ResponseEntity<>(updatedUserDto, HttpStatus.OK);
            }

            return response;
        } catch (UserService.UserCreationException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseEntity<>("An error occurred", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PutMapping("/userUpdate/{userId}")
    public ResponseEntity<Object> updateUserInfo(@PathVariable String userId, @RequestBody Map<String, Object> payload, @RequestHeader("Authorization") String token) {
        try {
            ResponseEntity<Object> response = userService.updateUserInfo(userId, payload, token);

            if (response.getStatusCode() == HttpStatus.OK) {
                UserDto updatedUserDto = userService.getUserById(userId);
                return new ResponseEntity<>(updatedUserDto, HttpStatus.OK);
            }

            return response;
        } catch (UserService.UserCreationException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseEntity<>("An error occurred", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @DeleteMapping("/delete/{userId}")
    public ResponseEntity<Object> deleteUser(@PathVariable String userId, @RequestHeader("Authorization") String token) {
        return userService.deleteUserById(userId, token);
    }

    @DeleteMapping("/delete/")
    public ResponseEntity<Object> noUserIdProvided() {
        Map<String, Object> responseBody = Map.of("message", "Please provide a user ID");
        return new ResponseEntity<>(responseBody, HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/login")
    public ResponseEntity<Object> login(@RequestBody Map<String, Object> payload) {

        try {
            System.out.println("Received payload:");
            payload.forEach((key, value) -> System.out.println(key + ": " + value));
            return new ResponseEntity<>(userService.loginUser(payload), HttpStatus.CREATED);
        } catch (UserService.UserCreationException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        } catch (Exception e) {
            return new ResponseEntity<>("An error occurred", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/login/pin")
    public ResponseEntity<Object> loginPin(@RequestBody Map<String, Object> payload) {
        try {
            System.out.println("Received payload:");
            payload.forEach((key, value) -> System.out.println(key + ": " + value));

            ResponseEntity<Object> loginResponse = userService.loginUserPin(payload);
            HttpStatus statusCode = (HttpStatus) loginResponse.getStatusCode();
            return new ResponseEntity<>(loginResponse.getBody(), statusCode);
        } catch (UserService.UserCreationException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        } catch (Exception e) {
            return new ResponseEntity<>("An error occurred", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

}