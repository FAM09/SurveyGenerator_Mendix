package oidc.implementation.common;

import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.systemwideinterfaces.core.IMendixObject;
import oidc.proxies.CacheMetadata;
import oidc.proxies.ClientConfiguration;
import oidc.proxies.ENUM_ClientAssertion;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class OIDCUtils {

    public static long getCacheUpdatedTime(IContext context) {
        List<IMendixObject> list = MendixDataStorageUtils.retrieveFromDatabase(context, "//%s",   new HashMap<>(),CacheMetadata.getType());
        if (!list.isEmpty()) {
            return CacheMetadata.initialize(context, list.stream().findFirst().get()).getCacheUpdateTime();
        }
        return -1;
    }

    public static List<IMendixObject> getPrivateKeySSOConfig(IContext context) {
        List<IMendixObject> list = MendixDataStorageUtils.retrieveFromDatabase(context, "//%s[%s = true() and %s = $ClientAssertion]",  new HashMap<>() {{
                    put("ClientAssertion", ENUM_ClientAssertion.PRIVATE_KEY.name());
                }},
                ClientConfiguration.getType(),
                ClientConfiguration.MemberNames.Active.name(),
                ClientConfiguration.MemberNames.ClientAssertion.name()
        );

        if (!list.isEmpty()) {
            return list;
        }

        return new ArrayList<>();
    }
}
