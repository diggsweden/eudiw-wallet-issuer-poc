package se.digg.eudiw.controllers;
import java.util.*;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
@Controller
public class AppDownloadController {
  @GetMapping("/app")
  public String app() {
    return "app";
  }
}