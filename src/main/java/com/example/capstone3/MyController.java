package com.example.capstone3;

import java.security.Principal;
import java.util.List;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class MyController {

  PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

  @Autowired private UserRepository userRepository;
  @Autowired private RoleRepository roleRepository;
  @Autowired private AccountRepository accountRepository;

  @GetMapping("/login")
  public String login() {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    if (auth != null && auth.isAuthenticated() && !auth.getName().equals("anonymousUser")) {
      return "redirect:/";
    }
    return "login";
  }

  @GetMapping("/")
  public String showMain(Model model, Principal principal) {
    if (principal == null) {
      return "redirect:/login";
    }

    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    boolean hasAdminRole = authentication.getAuthorities().stream()
        .anyMatch(r -> r.getAuthority().equals("ROLE_ADMIN"));
    boolean hasTellerRole = authentication.getAuthorities().stream()
        .anyMatch(r -> r.getAuthority().equals("ROLE_TELLER"));

    model.addAttribute("username", principal.getName());
    model.addAttribute("principal", principal);

    if (hasAdminRole) {
      List<User> usersList = (List<User>) userRepository.findAll();
      model.addAttribute("usersList", usersList);
      return "adminindex";
    } else if (hasTellerRole) {
      List<Account> accountList = accountRepository.findAllByOrderByCustomerAsc();
      model.addAttribute("accountList", accountList);
      return "tellerindex";
    }
    return "errorindex";
  }

  @RequestMapping("/new")
  public String addUser(User user, Model model) {
    model.addAttribute("user", user);
    List<Role> listRoles = (List<Role>) roleRepository.findAll();
    model.addAttribute("listRoles", listRoles);
    return "adduser";
  }

  @GetMapping("/edit/{id}")
  public String editUser(@PathVariable("id") Long id, Model model) {
    try {
      User user = userRepository.findById(id)
          .orElseThrow(() -> new RuntimeException("User not found"));
      List<Role> listRoles = (List<Role>) roleRepository.findAll();
      
      model.addAttribute("user", user);
      model.addAttribute("listRoles", listRoles);
      model.addAttribute("id", id);
      
      return "edituser";
    } catch (Exception e) {
      return "redirect:/?error=User not found";
    }
  }

  @PostMapping("/edit/{id}")
  public String save_editUser(
          @ModelAttribute("user") User user,
          @RequestParam("userRole") Long role_id,
          @PathVariable("id") Long id) {
    try {
      User existingUser = userRepository.findById(id)
          .orElseThrow(() -> new RuntimeException("User not found"));
      
      // Preserve existing password and enabled status
      user.setPassword(existingUser.getPassword());
      user.setEnabled(existingUser.isEnabled());
      
      // Set the new role
      Role newRole = roleRepository.findById(role_id)
          .orElseThrow(() -> new RuntimeException("Role not found"));
      user.setUserRoles(newRole);
      
      userRepository.save(user);
      return "redirect:/?success=User updated successfully";
    } catch (Exception e) {
      return "redirect:/?error=Failed to update user";
    }
  }

  @RequestMapping("/delete/{id}")
  public String delUser(@PathVariable("id") Long id, Model model) {
    userRepository.deleteById(id);
    return "redirect:/";
  }

  @RequestMapping("/save")
  public String saveUser(User user, Model model, @RequestParam("userRole") Long id) {
    Optional<User> db_user = userRepository.findByUsername(user.getUsername());
    if (db_user.isPresent()) {
      model.addAttribute("user", user);
      List<Role> listRoles = (List<Role>) roleRepository.findAll();
      model.addAttribute("listRoles", listRoles);
      model.addAttribute("error", "User already exists");
      return "adduser";
    }
    user.setUserRoles(roleRepository.findById(id).get());
    user.setPassword(passwordEncoder.encode(user.getPassword()));
    userRepository.save(user);
    return "redirect:/";
  }
}
