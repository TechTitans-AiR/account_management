package hr.techtitans.users.controllers;

import hr.techtitans.users.dtos.UserDto;
import hr.techtitans.users.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/users")
public class UserController {

    @Autowired
    private UserService userService;

    @GetMapping
    public ResponseEntity<List<UserDto>> getAllUsers() {
        return new ResponseEntity<List<UserDto>>(userService.allUsers(), HttpStatus.OK);
    }

    @GetMapping("/{userId}")
    public ResponseEntity<?> getUserById(@PathVariable String userId) {
        try {
            UserDto userDto = userService.getUserById(userId);

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
    public ResponseEntity<Object> addUser(@RequestBody Map<String, Object> payload) {
        try {
            return new ResponseEntity<>(userService.addUser(payload), HttpStatus.CREATED);
        } catch (UserService.UserCreationException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        } catch (Exception e) {
            return new ResponseEntity<>("An error occurred", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PutMapping("/update/{userId}")
    public ResponseEntity<Object> updateUser(@PathVariable String userId, @RequestBody Map<String, Object> payload) {
        try {
            ResponseEntity<Object> response = userService.updateUser(userId, payload);
            return response;
        } catch (UserService.UserCreationException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseEntity<>("An error occurred", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @DeleteMapping("/delete/{userId}")
    public ResponseEntity<Object> deleteUser(@PathVariable String userId) {
        return userService.deleteUserById(userId);
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
}