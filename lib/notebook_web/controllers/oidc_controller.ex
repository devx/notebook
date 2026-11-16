defmodule NotebookWeb.OIDCController do
  use NotebookWeb, :controller

  alias Notebook.Accounts
  alias NotebookWeb.UserAuth

  require Logger

  @doc """
  Initiates the Kanidm OIDC login flow by redirecting the user to Kanidm's OAuth2 authorization page.
  """
  def request(conn, _params) do
    state = :crypto.strong_rand_bytes(16) |> Base.url_encode64(padding: false)

    auth_url = System.get_env("NOTEBOOK_OIDC_AUTH_URL") || "https://auth.palmahq.com/ui/oauth2"
    client_id = System.get_env("NOTEBOOK_OIDC_CLIENT_ID") || "notebook"
    redirect_uri = System.get_env("NOTEBOOK_OIDC_REDIRECT_URI") || "https://notebook.palmahq.com/auth/kanidm/callback"

    query_params = %{
      "client_id" => client_id,
      "redirect_uri" => redirect_uri,
      "response_type" => "code",
      "scope" => "openid profile email",
      "state" => state
    }

    target = "#{auth_url}?#{URI.encode_query(query_params)}"

    conn
    |> put_session(:oidc_state, state)
    |> redirect(external: target)
  end

  @doc """
  Handles the callback from Kanidm with the authorization code.
  Exchanges code for access_token, retrieves user info, and logs the user in.
  """
  def callback(conn, %{"code" => code, "state" => state}) do
    expected_state = get_session(conn, :oidc_state)

    if expected_state && Plug.Crypto.secure_compare(expected_state, state) do
      conn = delete_session(conn, :oidc_state)
      exchange_code_and_login(conn, code)
    else
      Logger.error("OIDC state mismatch or missing state")

      conn
      |> delete_session(:oidc_state)
      |> put_flash(:error, "Authentication session expired or state mismatch. Please try again.")
      |> redirect(to: ~p"/users/log-in")
    end
  end

  def callback(conn, %{"error" => error} = params) do
    desc = params["error_description"] || error
    Logger.error("OIDC provider error: #{inspect(desc)}")

    conn
    |> put_flash(:error, "Authentication failed with identity provider: #{desc}")
    |> redirect(to: ~p"/users/log-in")
  end

  def callback(conn, _params) do
    conn
    |> put_flash(:error, "Invalid authentication response.")
    |> redirect(to: ~p"/users/log-in")
  end

  defp exchange_code_and_login(conn, code) do
    token_url = System.get_env("NOTEBOOK_OIDC_TOKEN_URL") || "https://auth.palmahq.com/oauth2/token"
    client_id = System.get_env("NOTEBOOK_OIDC_CLIENT_ID") || "notebook"
    client_secret = System.get_env("NOTEBOOK_OIDC_CLIENT_SECRET") || ""
    redirect_uri = System.get_env("NOTEBOOK_OIDC_REDIRECT_URI") || "https://notebook.palmahq.com/auth/kanidm/callback"
    userinfo_url = System.get_env("NOTEBOOK_OIDC_USERINFO_URL") || "https://auth.palmahq.com/oauth2/openid/notebook/userinfo"

    token_req =
      Req.post(token_url,
        form: [
          grant_type: "authorization_code",
          code: code,
          redirect_uri: redirect_uri,
          client_id: client_id
        ],
        auth: {:basic, "#{client_id}:#{client_secret}"}
      )

    case token_req do
      {:ok, %{status: 200, body: %{"access_token" => access_token}}} ->
        fetch_userinfo_and_login(conn, userinfo_url, access_token)

      {:ok, %{status: status, body: body}} ->
        Logger.error("OIDC token exchange failed status=#{status}: #{inspect(body)}")

        conn
        |> put_flash(:error, "Failed to authenticate with identity provider.")
        |> redirect(to: ~p"/users/log-in")

      {:error, reason} ->
        Logger.error("OIDC token exchange connection error: #{inspect(reason)}")

        conn
        |> put_flash(:error, "Connection to identity provider failed.")
        |> redirect(to: ~p"/users/log-in")
    end
  end

  defp fetch_userinfo_and_login(conn, userinfo_url, access_token) do
    case Req.get(userinfo_url, auth: {:bearer, access_token}) do
      {:ok, %{status: 200, body: userinfo}} ->
        handle_userinfo(conn, userinfo)

      {:ok, %{status: status, body: body}} ->
        Logger.error("OIDC userinfo failed status=#{status}: #{inspect(body)}")

        conn
        |> put_flash(:error, "Failed to retrieve user profile from identity provider.")
        |> redirect(to: ~p"/users/log-in")

      {:error, reason} ->
        Logger.error("OIDC userinfo connection error: #{inspect(reason)}")

        conn
        |> put_flash(:error, "Failed to connect to userinfo endpoint.")
        |> redirect(to: ~p"/users/log-in")
    end
  end

  defp handle_userinfo(conn, userinfo) do
    username = userinfo["preferred_username"] || userinfo["sub"] || "user"
    raw_name = userinfo["name"] || username
    name = if String.length(raw_name || "") >= 2, do: raw_name, else: "#{username}_user"
    email = String.downcase(userinfo["email"] || "#{username}@palmahq.com")

    case find_or_create_user(email, name) do
      {:ok, user} ->
        conn
        |> put_flash(:info, "Signed in successfully via Kanidm.")
        |> UserAuth.log_in_user(user)

      {:error, changeset} ->
        Logger.error("OIDC user creation failed: #{inspect(changeset)}")

        conn
        |> put_flash(:error, "Could not create user account for #{email}.")
        |> redirect(to: ~p"/users/log-in")
    end
  end

  defp find_or_create_user(email, name) do
    case Accounts.get_user_by_email(email) do
      nil ->
        random_password = :crypto.strong_rand_bytes(32) |> Base.encode64()

        Accounts.register_user(%{
          "name" => name,
          "email" => email,
          "password" => random_password
        })

      user ->
        {:ok, user}
    end
  end
end
