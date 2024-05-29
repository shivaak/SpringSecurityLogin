package com.demo.userlogin.springsecuritylogin.audit;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.*;
import org.aspectj.lang.reflect.MethodSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;

@Aspect
@Component
@RequiredArgsConstructor
@Slf4j
public class AuditAspect {

    private static final Logger auditLogger = LoggerFactory.getLogger("com.demo.userlogin.springsecuritylogin.audit");

    @Pointcut("@annotation(auditAnnotation)")
    public void auditPointcut(Audit auditAnnotation) {}

    @Before(value = "auditPointcut(auditAnnotation)", argNames = "joinPoint,auditAnnotation")
    public void logBefore(JoinPoint joinPoint, Audit auditAnnotation) {
        if (auditAnnotation.logPoint() == Audit.LogPoint.BOTH || auditAnnotation.logPoint() == Audit.LogPoint.BEFORE) {
            String username = getCurrentUsername();
            String action = auditAnnotation.action();
            String methodName = joinPoint.getSignature().getName();
            Method method = ((MethodSignature) joinPoint.getSignature()).getMethod();
            Object[] args = joinPoint.getArgs();

            String argsDetails = getAuditableFields(args, method);

            auditLogger.info("User '{}' is performing action '{}', method: '{}', arguments: '{}'", username, action, methodName, argsDetails);
        }
    }

    @AfterReturning(pointcut = "auditPointcut(auditAnnotation)", returning = "result", argNames = "joinPoint,auditAnnotation,result")
    public void logAfter(JoinPoint joinPoint, Audit auditAnnotation, Object result) {
        if (auditAnnotation.logPoint() == Audit.LogPoint.BOTH || auditAnnotation.logPoint() == Audit.LogPoint.AFTER) {
            String username = getCurrentUsername();
            String action = auditAnnotation.action();
            String methodName = joinPoint.getSignature().getName();
            Method method = ((MethodSignature) joinPoint.getSignature()).getMethod();

            String resultDetails = getAuditableResult(result);

            auditLogger.info("User '{}' has completed action '{}', method: '{}', result: '{}'", username, action, methodName, resultDetails);
        }
    }

    @AfterThrowing(pointcut = "auditPointcut(auditAnnotation)", throwing = "exception", argNames = "joinPoint,auditAnnotation,exception")
    public void logAfterThrowing(JoinPoint joinPoint, Audit auditAnnotation, Throwable exception) {
        if (auditAnnotation.logPoint() == Audit.LogPoint.BOTH || auditAnnotation.logPoint() == Audit.LogPoint.BEFORE) {
            String username = getCurrentUsername();
            String action = auditAnnotation.action();
            String methodName = joinPoint.getSignature().getName();
            Method method = ((MethodSignature) joinPoint.getSignature()).getMethod();
            Object[] args = joinPoint.getArgs();

            String argsDetails = getAuditableFields(args, method);

            auditLogger.error(
                    "User '{}' encountered an exception while performing action '{}', method: '{}', arguments: '{}', exception: '{}'",
                    username, action, methodName, argsDetails, exception.getMessage());
        }
    }

    private String getCurrentUsername() {
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            return "anonymousUser";
        }
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal instanceof UserDetails) {
            return ((UserDetails) principal).getUsername();
        }
        return principal.toString();
    }

    private String getAuditableFields(Object[] args, Method method) {
        if (args == null || method == null) {
            return "null";
        }

        StringBuilder result = new StringBuilder();

        // Get the parameters of the method
        Parameter[] parameters = method.getParameters();

        for (int i = 0; i < parameters.length; i++) {
            Parameter parameter = parameters[i];
            if (parameter.isAnnotationPresent(AuditableField.class)) {
                result.append(parameter.getName()).append("=").append(args[i]).append(", ");
            } else if (isPrimitiveOrWrapperType(args[i].getClass())) {
                result.append(parameter.getName()).append("=").append(args[i]).append(", ");
            } else {
                result.append(getFieldsWithAuditableAnnotation(args[i])).append(", ");
            }
        }

        return !result.isEmpty() ? result.substring(0, result.length() - 2) : "";
    }

    private String getAuditableResult(Object result) {
        if (result == null) {
            return "null";
        }

        StringBuilder resultDetails = new StringBuilder();

        if (isPrimitiveOrWrapperType(result.getClass())) {
            resultDetails.append(result.toString());
        } else {
            resultDetails.append(getFieldsWithAuditableAnnotation(result));
        }

        return resultDetails.toString();
    }

    private String getFieldsWithAuditableAnnotation(Object obj) {
        if (obj == null) {
            return "null";
        }

        StringBuilder result = new StringBuilder();
        Field[] fields = obj.getClass().getDeclaredFields();
        for (Field field : fields) {
            if (field.isAnnotationPresent(AuditableField.class)) {
                field.setAccessible(true);
                try {
                    result.append(field.getName()).append("=").append(field.get(obj)).append(", ");
                } catch (IllegalAccessException e) {
                    log.error("Could not access field: {}", field.getName(), e);
                }
            }
        }
        return result.toString();
    }

    private boolean isPrimitiveOrWrapperType(Class<?> clazz) {
        return clazz.isPrimitive() || clazz == String.class || clazz == Boolean.class || clazz == Integer.class
                || clazz == Long.class || clazz == Short.class || clazz == Byte.class || clazz == Character.class
                || clazz == Double.class || clazz == Float.class;
    }

}
