const API_BASE_URL = "http://localhost:8000";

export async function investigateNode(nodeId) {
  const response = await fetch(
    `${API_BASE_URL}/investigate`,
    {
      method: "POST",

      headers: {
        "Content-Type": "application/json",
      },

      body: JSON.stringify({
        node_id: nodeId,
      }),
    }
  );

  if (!response.ok) {
    throw new Error(
      "Investigation request failed"
    );
  }

  return await response.json();
}
