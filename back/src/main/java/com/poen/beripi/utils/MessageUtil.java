package com.poen.beripi.utils;

import java.util.Locale;

import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class MessageUtil {
    
    private final MessageSource messageSource;
    
    public MessageUtil(MessageSource messageSource) {
        this.messageSource = messageSource;
    }
    
    public String getMessage(String code) {
        Locale currentLocale = LocaleContextHolder.getLocale();
        log.info("=== MessageUtil ===");
        log.info("Getting message for code: {}", code);
        log.info("Current Locale: {}", currentLocale);
        String message = messageSource.getMessage(code, null, currentLocale);
        log.info("Resolved message: {}", message);
        return message;
    }
    
    public String getMessage(String code, Object... args) {
        return messageSource.getMessage(code, args, LocaleContextHolder.getLocale());
    }
    
    public String getMessage(String code, Locale locale) {
        return messageSource.getMessage(code, null, locale);
    }
    
    public String getMessage(String code, Locale locale, Object... args) {
        return messageSource.getMessage(code, args, locale);
    }
}
