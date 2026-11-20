# Proxy history filter for Hirdman Radar notes

With *Highlight hosts with leaks in Proxy history* turned on, Proxy responses from
hosts with High or Medium risk get a colour (red or orange) and a note such as
`Hirdman Radar: High risk, 12 infostealer records`. The colour and the note come
from the plugin's table only; nothing is sent anywhere. Items logged before the
host was checked are not changed.

To show only those items, open the filter bar in *Proxy > HTTP history*, switch
to *Script mode* and paste:

```java
var annotations = requestResponse.annotations();
return annotations.hasNotes() && annotations.notes().contains("Hirdman Radar:");
```

For High risk only, look for `"Hirdman Radar: High"` instead.

To keep it in *Extensions > Bambda library*, save this as
`hirdman-radar-leaks.bambda` and import it:

```yaml
id: cb8fc95e-e14a-4b50-8332-7039c77cd85c
name: Hirdman Radar hosts with leaks
function: VIEW_FILTER
location: PROXY_HTTP_HISTORY
source: |+
  var annotations = requestResponse.annotations();
  return annotations.hasNotes() && annotations.notes().contains("Hirdman Radar:");
```
