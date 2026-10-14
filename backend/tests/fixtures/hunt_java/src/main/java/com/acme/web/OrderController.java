package com.acme.web;

import com.acme.service.OrderService;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

@RestController
@RequestMapping("/orders")
public class OrderController {
    private static final String BASE = "/var/app/exports";
    private OrderService orderService;

    @GetMapping("/search")
    public String search(@RequestParam("q") String q) {
        return orderService.search(q);
    }

    @GetMapping("/export")
    public byte[] export(@RequestParam("name") String name) throws Exception {
        Path target = Paths.get(BASE, name);
        return java.nio.file.Files.readAllBytes(target);
    }

    @GetMapping("/echo")
    public ResponseEntity<String> echo(@RequestParam("msg") String msg) {
        return new ResponseEntity<>("Unknown order: " + msg, HttpStatus.BAD_REQUEST);
    }

    @GetMapping("/echo-safe")
    public ResponseEntity<String> echoSafe(@RequestParam("msg") String msg) {
        return new ResponseEntity<>("Unknown order: " + HtmlUtils.htmlEscape(msg), HttpStatus.BAD_REQUEST);
    }

    @DeleteMapping("/admin/{id}")
    public void deleteOrder(@PathVariable("id") long id) {
        orderService.delete(id);
    }
}
