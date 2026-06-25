package oidc.implementation.common;

import com.mendix.systemwideinterfaces.core.IContext;
import oidc.proxies.Role;

import java.text.ParseException;
import java.util.List;
import java.util.stream.Collectors;

public final class RoleAssignmentUtil {

   public static List<Role> getIdpRolesFromToken(final IContext context, final String encodedToken, final String name) throws ParseException {

       List<String> roleNames = TokenUtils.getClaimValueAsStringArray(encodedToken, name);
       if (roleNames == null) {
           return java.util.Collections.emptyList();
       }
       return roleNames.stream()
               .map(roleName -> {
                   Role role = new Role(context);
                   role.setRoleName(roleName);
                   return role;
               })
               .collect(Collectors.toList());
       }
}
