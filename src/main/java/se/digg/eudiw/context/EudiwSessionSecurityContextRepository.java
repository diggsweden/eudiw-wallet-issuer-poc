package se.digg.eudiw.context;

import java.util.Map;
import java.util.HashMap;

import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.DeferredSecurityContext;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.security.core.context.SecurityContext;

import jakarta.servlet.http.HttpServletRequest;

@Component
public class EudiwSessionSecurityContextRepository extends HttpSessionSecurityContextRepository {
  Logger logger = LoggerFactory.getLogger(EudiwSessionSecurityContextRepository.class);

  // TODO serialize/deserialize context och spara i redis
  Map<String, SecurityContext> pendingContexts = new HashMap<String, SecurityContext>();

  public EudiwSessionSecurityContextRepository() {
    super();
  }

  @Override
  public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
    logger.info("Load security context: {}", requestResponseHolder.getRequest().getRequestURI());
    SecurityContext securityContext = super.loadContext(requestResponseHolder);
    logger.info("Loaded security context: {}", securityContext);

    return securityContext;
  }

  @Override
  public void saveContext(SecurityContext context, HttpServletRequest request,
      HttpServletResponse response) {
    logger.info("Save security context: {}", context);

    super.saveContext(context, request, response);
  }

  @Override
  public DeferredSecurityContext loadDeferredContext(HttpServletRequest request) {
    logger.info("Load security context: {}", request.getRequestURI());
    SecurityContext ctx = readSecurityContextFromPath(request);
    if (ctx != null) {
      logger.info("Loaded security context: {}", ctx);
      return new PathDeferredSecurityContext(ctx);
    }
    logger.info("No specific eudiw context: {}", ctx);
    DeferredSecurityContext deferredSecurityContext = super.loadDeferredContext(request);
    logger.info("Security context from superclass: {}",
        deferredSecurityContext.get().getAuthentication());
    return deferredSecurityContext;
  }

  private SecurityContext readSecurityContextFromPath(HttpServletRequest request) {
    String reqUri = request.getRequestURI();
    logger.trace("reqUri: {}", reqUri);
    if (reqUri != null && reqUri.startsWith("/auth/return/")) {
      String[] tokenizer = reqUri.split("/");
      if (tokenizer.length == 4) {
        String authenticationId = tokenizer[3];
        SecurityContext context = pendingContexts.get(authenticationId);
        if (context != null) {
          pendingContexts.remove(authenticationId);
          logger.trace("Found security context for path: {}", reqUri);

          return context;
        }
      }
    }
    logger.trace("Did not find security context in path: {}", reqUri);
    return null;
  }

  public void addPendingContext(String authenticationId, SecurityContext context) {
    pendingContexts.put(authenticationId, context);
  }

}
