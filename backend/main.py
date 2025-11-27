from dotenv import load_dotenv

# Load environment variables FIRST before any other imports
load_dotenv()

from fastapi import FastAPI, HTTPException, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
import os
import secrets
from typing import Optional

from models.schemas import (
    GenerateRequest,
    GenerateResponse,
    PostRequest,
    PostResponse,
    HistoryResponse,
    PostHistoryItem,
    TweetHistoryItem
)
from auth.supabase_auth import get_current_user
from agent.graph import run_agent
from storage.tweet_storage import TweetStorage
from services.social.twitter_service import TwitterOAuthService
from services.social.github_service import GitHubOAuthService
from services.social.linkedin_service import LinkedInOAuthService
from services.supabase_service import supabase_service
from services.github_data_service import GitHubDataService
from services.twitter_data_service import twitter_data_service
from services.twitter_analysis_service import twitter_analysis_service
from services.context_service import ContextService
from services.embedding_service import get_embedding_service
from services.embedding_job_service import get_embedding_job_service
from services.subscription_service import get_subscription_service
from services.razorpay_service import get_razorpay_service

# Validate Razorpay configuration at startup
try:
    razorpay_service = get_razorpay_service()
except ValueError as e:
    print(f"❌ Razorpay configuration error: {e}")
    print("Please set RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET in your .env file")
    raise

# Initialize FastAPI app
app = FastAPI(
    title="Mataroo.com API",
    description="AI-powered social media content generator with agentic workflows",
    version="1.0.0"
)

# Configure CORS
cors_origins = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize services
tweet_storage = TweetStorage()
twitter_oauth = TwitterOAuthService()
github_oauth = GitHubOAuthService()
linkedin_oauth = LinkedInOAuthService()
github_data_service = GitHubDataService()
context_service = ContextService()

# Store OAuth states temporarily (in production, use Redis or database)
oauth_states = {}


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "Mataroo.com API",
        "version": "1.0.0",
        "status": "running"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}


@app.post("/api/generate", response_model=GenerateResponse)
async def generate_content(
    request: GenerateRequest,
    authorization: Optional[str] = Header(None)
):
    """
    Generate content using the agentic AI workflow.
    
    Args:
        request: GenerateRequest with user prompt and platform
        authorization: JWT token in Authorization header
        
    Returns:
        GenerateResponse with generated content data
    """
    try:
        # Verify user is authenticated
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        token = authorization.split(" ")[1]
        user_data = supabase_service.verify_jwt_token(token)
        user_id = user_data.get("sub")
        
        print(f"\n📝 User {user_id} - Received prompt for {request.platform}: {request.prompt}")
        
        # Run the agent with platform parameter and user_id for RAG context
        final_state = await run_agent(request.prompt, request.platform, user_id)
        
        # Check if generation was successful
        if not final_state.get("is_valid"):
            error_msg = final_state.get("error", "Content generation failed")
            return GenerateResponse(
                success=False,
                error=error_msg
            )
        
        # Return the generated content data
        return GenerateResponse(
            success=True,
            data={
                "platform": request.platform,
                "content": final_state.get("tweet_content", ""),
                "hashtags": final_state.get("hashtags", []),
                "final_content": final_state.get("final_content", ""),
                "char_count": final_state.get("char_count", 0),
            }
        )
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error in generate endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/post", response_model=PostResponse)
async def post_content(
    request: PostRequest,
    authorization: Optional[str] = Header(None)
):
    """
    Post the generated content to the specified platform using user's connected account.
    
    Args:
        request: PostRequest with content, platform, and hashtags
        authorization: JWT token in Authorization header
        
    Returns:
        PostResponse with post URL
    """
    try:
        # Verify user is authenticated
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        token = authorization.split(" ")[1]
        user_data = supabase_service.verify_jwt_token(token)
        user_id = user_data.get("sub")
        
        print(f"\n🚀 User {user_id} - Posting to {request.platform}: {request.content[:50]}...")
        
        # Check subscription limit before posting
        subscription_service = get_subscription_service()
        can_post, message = subscription_service.can_user_post(user_id)
        
        if not can_post:
            raise HTTPException(
                status_code=403,
                detail=message
            )
        
        # Get user's connected account for this platform
        account = supabase_service.get_platform_connection(user_id, request.platform)
        
        if not account:
            raise HTTPException(
                status_code=400,
                detail=f"No {request.platform} account connected. Please connect your account first."
            )
        
        if not account.get("is_active"):
            raise HTTPException(
                status_code=400,
                detail=f"Your {request.platform} account is not active. Please reconnect."
            )
        
        # Debug: Check what fields we have
        print(f"📊 Account data fields: {list(account.keys())}")
        print(f"📊 Has expires_at: {account.get('expires_at') is not None}")
        print(f"📊 Has refresh_token: {account.get('refresh_token') is not None}")
        
        # Post to platform using user's tokens
        result = None
        if request.platform == "twitter":
            # Use Twitter OAuth service with user's access token
            twitter_oauth = TwitterOAuthService()
            
            # Check if token is expired and refresh if needed
            access_token = account["access_token"]
            if account.get("expires_at"):
                from datetime import datetime, timezone
                
                # Parse the expires_at timestamp
                expires_at_str = account["expires_at"]
                if isinstance(expires_at_str, str):
                    # Handle ISO format with or without timezone
                    if expires_at_str.endswith('Z'):
                        expires_at_str = expires_at_str.replace('Z', '+00:00')
                    expires_at = datetime.fromisoformat(expires_at_str)
                    # Ensure it's timezone-aware
                    if expires_at.tzinfo is None:
                        expires_at = expires_at.replace(tzinfo=timezone.utc)
                else:
                    expires_at = expires_at_str
                
                if twitter_oauth.is_token_expired(expires_at):
                    print(f"🔄 Token expired, refreshing for user {user_id}...")
                    try:
                        # Refresh the token
                        token_response = await twitter_oauth.refresh_access_token(account["refresh_token"])
                        
                        # Update the access token
                        access_token = token_response["access_token"]
                        
                        # Update tokens in database
                        new_expires_at = twitter_oauth.calculate_token_expiry(token_response.get("expires_in", 7200))
                        supabase_service.update_platform_tokens(
                            user_id,
                            request.platform,
                            access_token,
                            token_response.get("refresh_token", account["refresh_token"]),
                            new_expires_at
                        )
                        print(f"✅ Token refreshed successfully for user {user_id}")
                    except Exception as e:
                        print(f"❌ Failed to refresh token: {str(e)}")
                        raise HTTPException(
                            status_code=401,
                            detail="Your session has expired. Please reconnect your account."
                        )
            
            result = await twitter_oauth.post_tweet(
                request.content,
                access_token
            )
        elif request.platform == "linkedin":
            # LinkedIn posting
            linkedin_oauth = LinkedInOAuthService()
            
            # Check if token is expired and refresh if needed
            access_token = account["access_token"]
            if account.get("expires_at"):
                from datetime import datetime, timezone
                
                # Parse the expires_at timestamp
                expires_at_str = account["expires_at"]
                if isinstance(expires_at_str, str):
                    # Handle ISO format with or without timezone
                    if expires_at_str.endswith('Z'):
                        expires_at_str = expires_at_str.replace('Z', '+00:00')
                    expires_at = datetime.fromisoformat(expires_at_str)
                    # Ensure it's timezone-aware
                    if expires_at.tzinfo is None:
                        expires_at = expires_at.replace(tzinfo=timezone.utc)
                else:
                    expires_at = expires_at_str
                
                if linkedin_oauth.is_token_expired(expires_at):
                    print(f"🔄 Token expired, refreshing for user {user_id}...")
                    # LinkedIn tokens are long-lived (60 days) and usually require re-auth
                    # But if we had a refresh flow, it would go here.
                    # For now, we'll ask user to reconnect if expired
                    raise HTTPException(
                        status_code=401,
                        detail="Your LinkedIn session has expired. Please reconnect your account."
                    )
            
            # We need the user's URN (ID) to post
            user_urn = account["platform_user_id"]
            
            result = await linkedin_oauth.post_content(
                request.content,
                access_token,
                user_urn
            )
        elif request.platform == "reddit":
            # Reddit posting will be implemented in Phase 3
            raise HTTPException(status_code=501, detail="Reddit posting not yet implemented")
        
        if not result:
            raise HTTPException(status_code=500, detail="Failed to post content")
        
        # Save to Supabase
        post_data = {
            "user_id": user_id,
            "platform": request.platform,
            "user_prompt": request.user_prompt,
            "generated_content": request.content,
            "hashtags": request.hashtags or [],
            "platform_post_id": result.get("post_id") or result.get("tweet_id"),
            "platform_post_url": result.get("url"),
            "status": "posted"
        }
        
        post_id = supabase_service.save_post(post_data)
        
        # Increment post count after successful post
        subscription_service.increment_post_count(user_id)
        
        print(f"✅ Posted successfully to {request.platform}: {result.get('url')}")
        
        return PostResponse(
            success=True,
            post_id=result.get("post_id") or result.get("tweet_id"),
            url=result.get("url")
        )
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error posting content: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/history", response_model=HistoryResponse)
async def get_post_history(
    authorization: Optional[str] = Header(None),
    platform: Optional[str] = None,
    limit: int = 50
):
    """
    Get user's post history from Supabase.
    
    Args:
        authorization: JWT token in Authorization header
        platform: Optional filter by platform
        limit: Maximum number of posts to return
        
    Returns:
        HistoryResponse with list of posts
    """
    try:
        # Verify user is authenticated
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        token = authorization.split(" ")[1]
        user_data = supabase_service.verify_jwt_token(token)
        user_id = user_data.get("sub")
        
        # Get posts from Supabase
        posts_data = supabase_service.get_user_posts(user_id, platform, limit)
        
        # Convert to PostHistoryItem models
        posts = []
        for post in posts_data:
            posts.append(PostHistoryItem(
                id=post.get("id"),
                platform=post.get("platform"),
                user_prompt=post.get("user_prompt", ""),
                generated_content=post.get("generated_content", ""),
                hashtags=post.get("hashtags", []),
                platform_post_id=post.get("platform_post_id"),
                platform_post_url=post.get("platform_post_url"),
                status=post.get("status", "posted"),
                created_at=post.get("created_at", "")
            ))
        
        return HistoryResponse(
            success=True,
            posts=posts
        )
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error getting history: {str(e)}")
        return HistoryResponse(
            success=False,
            error=str(e),
            posts=[]
        )


@app.get("/api/auth/twitter/login")
async def twitter_login(authorization: Optional[str] = Header(None)):
    """
    Initiate Twitter OAuth flow.
    Requires user to be authenticated (JWT token in Authorization header).
    """
    try:
        # Verify user is authenticated
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        token = authorization.split(" ")[1]
        user_data = supabase_service.verify_jwt_token(token)
        user_id = user_data.get("sub")
        
        # Generate state for CSRF protection
        state = secrets.token_urlsafe(32)
        
        # Get authorization URL
        auth_url, code_verifier, state = twitter_oauth.get_authorization_url(state)
        
        # Store state and code_verifier temporarily
        oauth_states[state] = {
            "user_id": user_id,
            "code_verifier": code_verifier
        }
        
        # Return auth URL for frontend to redirect
        return {
            "success": True,
            "auth_url": auth_url
        }
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error initiating Twitter OAuth: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/auth/twitter/callback")
async def twitter_callback(
    code: str = Query(...),
    state: str = Query(...)
):
    """
    Handle Twitter OAuth callback.
    Exchange code for tokens and save to database.
    """
    try:
        # Verify state
        if state not in oauth_states:
            raise HTTPException(status_code=400, detail="Invalid state parameter")
        
        oauth_data = oauth_states[state]
        user_id = oauth_data["user_id"]
        code_verifier = oauth_data["code_verifier"]
        
        # Exchange code for tokens
        token_response = await twitter_oauth.exchange_code_for_token(code, code_verifier)
        
        # Get user info from Twitter
        user_info = await twitter_oauth.get_user_info(token_response["access_token"])
        twitter_user = user_info["data"]
        
        # Calculate token expiry
        expires_at = twitter_oauth.calculate_token_expiry(token_response["expires_in"])
        
        # Save to database
        account_data = {
            "user_id": user_id,
            "platform": "twitter",
            "platform_user_id": twitter_user["id"],
            "platform_username": twitter_user["username"],
            "access_token": token_response["access_token"],
            "refresh_token": token_response.get("refresh_token"),
            "expires_at": expires_at.isoformat(),  # Fixed: was token_expires_at
            "scope": token_response.get("scope", "").split(),
            "is_active": True
        }
        
        success = supabase_service.save_connected_account(account_data)
        
        if not success:
            raise HTTPException(status_code=500, detail="Failed to save connection")
        
        # Clean up state
        del oauth_states[state]
        
        # Redirect to frontend success page
        frontend_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
        return RedirectResponse(url=f"{frontend_url}/settings?connected=twitter")
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error in Twitter callback: {str(e)}")
        frontend_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
        return RedirectResponse(url=f"{frontend_url}/settings?error={str(e)}")


@app.post("/api/twitter/fetch-tweets")
async def fetch_twitter_tweets(
    authorization: Optional[str] = Header(None),
    limit: int = Query(20, ge=1, le=100)
):
    """
    Fetch user's tweets from Twitter and save to database.
    
    Args:
        authorization: JWT token in Authorization header
        limit: Number of tweets to fetch (default 20, max 100)
        
    Returns:
        dict: Summary of fetched tweets
    """
    try:
        # Verify user is authenticated
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        token = authorization.split(" ")[1]
        user_data = supabase_service.verify_jwt_token(token)
        user_id = user_data.get("sub")
        
        print(f"\n🐦 Fetching tweets for user {user_id}...")
        
        # Get user's Twitter connection
        account = supabase_service.get_connected_account(user_id, "twitter")
        if not account:
            raise HTTPException(
                status_code=404,
                detail="Twitter account not connected. Please connect your Twitter account first."
            )
        
        access_token = account.get("access_token")
        if not access_token:
            raise HTTPException(status_code=401, detail="No valid Twitter access token found")
        
        # Check if token is expired and refresh if needed
        expires_at = account.get("expires_at")
        if expires_at:
            from datetime import datetime
            if isinstance(expires_at, str):
                expires_at = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
            
            if twitter_oauth.is_token_expired(expires_at):
                print(f"🔄 Token expired, refreshing for user {user_id}...")
                try:
                    token_response = await twitter_oauth.refresh_access_token(account["refresh_token"])
                    access_token = token_response["access_token"]
                    
                    # Update tokens in database
                    new_expires_at = twitter_oauth.calculate_token_expiry(token_response.get("expires_in", 7200))
                    supabase_service.update_platform_tokens(
                        user_id,
                        "twitter",
                        access_token,
                        token_response.get("refresh_token", account["refresh_token"]),
                        new_expires_at
                    )
                    print(f"✅ Token refreshed successfully")
                except Exception as e:
                    print(f"❌ Failed to refresh token: {str(e)}")
                    raise HTTPException(
                        status_code=401,
                        detail="Your Twitter session has expired. Please reconnect your account."
                    )
        
        # Fetch tweets from Twitter API
        print(f"📥 Fetching {limit} tweets from Twitter API...")
        try:
            tweets_response = await twitter_oauth.batch_fetch_all_tweets(
                access_token=access_token,
                limit=limit
            )
        except Exception as fetch_error:
            error_msg = str(fetch_error)
            print(f"❌ Twitter API Error: {error_msg}")
            
            # Check for rate limit error
            if "429" in error_msg or "Too Many Requests" in error_msg:
                raise HTTPException(
                    status_code=429,
                    detail="Twitter API rate limit reached. Please wait 15 minutes and try again. Twitter allows limited requests per 15-minute window."
                )
            
            # Re-raise other errors
            raise
        
        tweets_data = tweets_response.get("data", [])
        total_fetched = len(tweets_data)
        
        if not tweets_data:
            return {
                "success": True,
                "message": "No tweets found",
                "total_fetched": 0,
                "new_tweets": 0,
                "existing_tweets": 0
            }
        
        print(f"✅ Fetched {total_fetched} tweets from Twitter")
        
        # Save tweets to database
        print(f"💾 Saving tweets to database...")
        save_result = await twitter_data_service.save_twitter_tweets(
            user_id=user_id,
            tweets_data=tweets_data
        )
        
        # Get the most recent tweet ID
        most_recent_tweet_id = tweets_data[0].get("id") if tweets_data else None
        
        # Update fetch log
        await twitter_data_service.update_twitter_fetch_log(
            user_id=user_id,
            last_tweet_id=most_recent_tweet_id,
            total_count=save_result["new_tweets"],
            fetch_type="manual"
        )
        
        print(f"✅ Saved {save_result['new_tweets']} new tweets, {save_result['existing_tweets']} already existed")
        
        # Generate style profile automatically
        print(f"🎨 Generating style profile...")
        try:
            style_profile = await twitter_analysis_service.generate_style_profile(user_id)
            print(f"✅ Style profile generated")
        except Exception as e:
            print(f"⚠️  Warning: Failed to generate style profile: {str(e)}")
            # Don't fail the whole request if style profile generation fails
        
        return {
            "success": True,
            "message": f"Successfully fetched {total_fetched} tweets",
            "total_fetched": total_fetched,
            "new_tweets": save_result["new_tweets"],
            "existing_tweets": save_result["existing_tweets"],
            "errors": save_result.get("errors", [])
        }
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error fetching tweets: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/twitter/tweets")
async def get_user_tweets(
    authorization: Optional[str] = Header(None),
    limit: int = Query(100, ge=1, le=1000)
):
    """
    Get user's stored tweets from database.
    
    Args:
        authorization: JWT token in Authorization header
        limit: Number of tweets to retrieve (default 100)
        
    Returns:
        dict: List of stored tweets
    """
    try:
        # Verify user is authenticated
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        token = authorization.split(" ")[1]
        user_data = supabase_service.verify_jwt_token(token)
        user_id = user_data.get("sub")
        
        # Get tweets from database
        tweets = await twitter_data_service.get_user_tweets_from_db(user_id, limit)
        
        # Get stats
        stats = await twitter_data_service.get_tweet_stats(user_id)
        
        # Get fetch log
        fetch_log = await twitter_data_service.get_fetch_log(user_id)
        
        return {
            "success": True,
            "tweets": tweets,
            "stats": stats,
            "fetch_log": fetch_log
        }
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error getting tweets: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/twitter/style-profile")
async def get_twitter_style_profile(
    authorization: Optional[str] = Header(None)
):
    """
    Get user's Twitter style profile.
    
    Args:
        authorization: JWT token in Authorization header
        
    Returns:
        dict: Style profile with writing patterns and preferences
    """
    try:
        # Verify user is authenticated
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        token = authorization.split(" ")[1]
        user_data = supabase_service.verify_jwt_token(token)
        user_id = user_data.get("sub")
        
        # Get style profile
        profile = await twitter_analysis_service.get_style_profile(user_id)
        
        if not profile:
            # Try to generate if doesn't exist
            print(f"📊 No style profile found, generating...")
            profile = await twitter_analysis_service.generate_style_profile(user_id)
            
            if profile.get("error"):
                raise HTTPException(
                    status_code=404,
                    detail="No style profile available. Please fetch your tweets first."
                )
        
        return {
            "success": True,
            "profile": profile
        }
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error getting style profile: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/twitter/regenerate-style-profile")
async def regenerate_style_profile(
    authorization: Optional[str] = Header(None)
):
    """
    Regenerate user's Twitter style profile.
    
    Args:
        authorization: JWT token in Authorization header
        
    Returns:
        dict: Newly generated style profile
    """
    try:
        # Verify user is authenticated
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        token = authorization.split(" ")[1]
        user_data = supabase_service.verify_jwt_token(token)
        user_id = user_data.get("sub")
        
        print(f"\n🔄 Regenerating style profile for user {user_id}...")
        
        # Generate new profile
        profile = await twitter_analysis_service.generate_style_profile(user_id)
        
        if profile.get("error"):
            raise HTTPException(
                status_code=400,
                detail=profile.get("error", "Failed to generate style profile")
            )
        
        return {
            "success": True,
            "message": "Style profile regenerated successfully",
            "profile": profile
        }
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error regenerating style profile: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/auth/linkedin/login")
async def linkedin_login(authorization: Optional[str] = Header(None)):
    """
    Initiate LinkedIn OAuth flow.
    Requires user to be authenticated (JWT token in Authorization header).
    """
    try:
        # Verify user is authenticated
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        token = authorization.split(" ")[1]
        user_data = supabase_service.verify_jwt_token(token)
        user_id = user_data.get("sub")
        
        # Generate state for CSRF protection
        state = secrets.token_urlsafe(32)
        
        # Get authorization URL
        auth_url, state = linkedin_oauth.get_authorization_url(state)
        
        # Store state temporarily
        oauth_states[state] = {
            "user_id": user_id
        }
        
        # Return auth URL for frontend to redirect
        return {
            "success": True,
            "auth_url": auth_url
        }
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error initiating LinkedIn OAuth: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/auth/linkedin/callback")
async def linkedin_callback(
    code: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    error: Optional[str] = Query(None),
    error_description: Optional[str] = Query(None)
):
    """
    Handle LinkedIn OAuth callback.
    Exchange code for tokens and save to database.
    """
    try:
        # Handle OAuth errors
        if error:
            print(f"❌ LinkedIn OAuth error: {error} - {error_description}")
            frontend_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
            return RedirectResponse(url=f"{frontend_url}/settings?error={error_description or error}")
            
        if not code or not state:
            raise HTTPException(status_code=400, detail="Missing code or state parameter")

        # Verify state
        if state not in oauth_states:
            raise HTTPException(status_code=400, detail="Invalid state parameter")
        
        oauth_data = oauth_states[state]
        user_id = oauth_data["user_id"]
        
        # Exchange code for tokens
        token_response = await linkedin_oauth.exchange_code_for_token(code)
        
        # Get user info from LinkedIn
        user_info = await linkedin_oauth.get_user_info(token_response["access_token"])
        
        # Calculate token expiry
        expires_at = linkedin_oauth.calculate_token_expiry(token_response["expires_in"])
        
        # Save to database
        account_data = {
            "user_id": user_id,
            "platform": "linkedin",
            "platform_user_id": user_info["sub"], # LinkedIn uses 'sub' as user ID
            "platform_username": user_info.get("name", "LinkedIn User"),
            "access_token": token_response["access_token"],
            "refresh_token": token_response.get("refresh_token"), # LinkedIn might not return this for all flows
            "expires_at": expires_at.isoformat(),
            "scope": token_response.get("scope", "").split(),
            "is_active": True
        }
        
        success = supabase_service.save_connected_account(account_data)
        
        if not success:
            raise HTTPException(status_code=500, detail="Failed to save connection")
        
        # Clean up state
        del oauth_states[state]
        
        # Redirect to frontend success page
        frontend_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
        return RedirectResponse(url=f"{frontend_url}/settings?connected=linkedin")
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error in LinkedIn callback: {str(e)}")
        frontend_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
        return RedirectResponse(url=f"{frontend_url}/settings?error={str(e)}")


@app.get("/api/auth/github/login")
async def github_login(authorization: Optional[str] = Header(None)):
    """
    Initiate GitHub OAuth flow.
    Requires user to be authenticated (JWT token in Authorization header).
    """
    try:
        # Verify user is authenticated
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        token = authorization.split(" ")[1]
        user_data = supabase_service.verify_jwt_token(token)
        user_id = user_data.get("sub")
        
        # Generate state for CSRF protection
        state = secrets.token_urlsafe(32)
        
        # Get authorization URL
        auth_url, state = github_oauth.get_authorization_url(state)
        
        # Store state temporarily
        oauth_states[state] = {
            "user_id": user_id
        }
        
        # Return auth URL for frontend to redirect
        return {
            "success": True,
            "auth_url": auth_url
        }
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error initiating GitHub OAuth: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/auth/github/callback")
async def github_callback(
    code: str = Query(...),
    state: str = Query(...)
):
    """
    Handle GitHub OAuth callback.
    Exchange code for tokens and save to database.
    """
    try:
        # Verify state
        if state not in oauth_states:
            raise HTTPException(status_code=400, detail="Invalid state parameter")
        
        oauth_data = oauth_states[state]
        user_id = oauth_data["user_id"]
        
        # Exchange code for tokens
        token_response = await github_oauth.exchange_code_for_token(code)
        
        # Get user info from GitHub
        user_info = await github_oauth.get_user_info(token_response["access_token"])
        
        # Save to database
        account_data = {
            "user_id": user_id,
            "platform": "github",
            "platform_user_id": str(user_info["id"]),
            "platform_username": user_info["login"],
            "access_token": token_response["access_token"],
            "refresh_token": None,  # GitHub doesn't use refresh tokens by default
            "expires_at": None,  # GitHub tokens don't expire by default
            "scope": token_response.get("scope", "").split(","),
            "is_active": True
        }
        
        success = supabase_service.save_connected_account(account_data)
        
        if not success:
            raise HTTPException(status_code=500, detail="Failed to save connection")
        
        # Clean up state
        del oauth_states[state]
        
        # Redirect to frontend success page
        frontend_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
        return RedirectResponse(url=f"{frontend_url}/settings?connected=github")
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error in GitHub callback: {str(e)}")
        frontend_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
        return RedirectResponse(url=f"{frontend_url}/settings?error={str(e)}")


@app.get("/api/connections")
async def get_connections(authorization: Optional[str] = Header(None)):
    """
    Get user's connected social media accounts.
    """
    try:
        # Verify user is authenticated
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        token = authorization.split(" ")[1]
        user_data = supabase_service.verify_jwt_token(token)
        user_id = user_data.get("sub")
        
        # Get connected accounts
        accounts = supabase_service.get_connected_accounts(user_id)
        
        # Remove sensitive data
        safe_accounts = []
        for account in accounts:
            safe_accounts.append({
                "platform": account["platform"],
                "platform_username": account.get("platform_username"),
                "is_active": account.get("is_active", True),
                "connected_at": account.get("connected_at")
            })
        
        return {
            "success": True,
            "connections": safe_accounts
        }
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error getting connections: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/connections/{platform}")
async def disconnect_account(
    platform: str,
    authorization: Optional[str] = Header(None)
):
    """
    Disconnect a social media account and clean up all related data.
    """
    try:
        # Verify user is authenticated
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        token = authorization.split(" ")[1]
        user_data = supabase_service.verify_jwt_token(token)
        user_id = user_data.get("sub")
        
        print(f"\n🔌 User {user_id} - Disconnecting {platform}...")
        
        # Get account to revoke token
        account = supabase_service.get_platform_connection(user_id, platform)
        
        if account and platform == "twitter":
            # Revoke token on Twitter
            await twitter_oauth.revoke_token(account["access_token"])
        
        # Delete from database
        success = supabase_service.delete_connected_account(user_id, platform)
        
        if not success:
            raise HTTPException(status_code=500, detail="Failed to disconnect account")
        
        # Clean up platform-specific data
        if platform == "github":
            print(f"🗑️  Cleaning up GitHub data...")
            try:
                # Delete all GitHub commits
                result = supabase_service.client.table("github_activity").delete().eq(
                    "user_id", user_id
                ).execute()
                commits_deleted = len(result.data) if result.data else 0
                print(f"✅ Deleted {commits_deleted} commits")
                
                # Delete fetch logs
                result = supabase_service.client.table("github_data_fetch_log").delete().eq(
                    "user_id", user_id
                ).execute()
                logs_deleted = len(result.data) if result.data else 0
                print(f"✅ Deleted {logs_deleted} fetch logs")
                
                # Delete user context
                result = supabase_service.client.table("user_context").delete().eq(
                    "user_id", user_id
                ).execute()
                context_deleted = len(result.data) if result.data else 0
                print(f"✅ Deleted user context")
                
                print(f"✅ All GitHub data cleaned up successfully")
            except Exception as e:
                print(f"⚠️  Warning: Failed to clean up some GitHub data: {str(e)}")
                import traceback
                traceback.print_exc()
                # Don't fail the disconnect if cleanup fails
        
        return {
            "success": True,
            "message": f"{platform.capitalize()} account disconnected and data cleaned up"
        }
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error disconnecting account: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/github/fetch-data")
async def fetch_github_data(
    authorization: Optional[str] = Header(None),
    days: int = 30
):
    """
    Fetch GitHub commits and store in database.
    
    Args:
        authorization: JWT token in Authorization header
        days: Number of days to fetch (default: 30)
        
    Returns:
        Success message with count of commits fetched
    """
    try:
        # Verify user is authenticated
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        token = authorization.split(" ")[1]
        user_data = supabase_service.verify_jwt_token(token)
        user_id = user_data.get("sub")
        
        print(f"\n📦 User {user_id} - Fetching GitHub data...")
        
        # Get user's GitHub connection
        github_account = supabase_service.get_platform_connection(user_id, "github")
        
        if not github_account:
            raise HTTPException(
                status_code=400,
                detail="No GitHub account connected. Please connect your account first."
            )
        
        if not github_account.get("is_active"):
            raise HTTPException(
                status_code=400,
                detail="Your GitHub account is not active. Please reconnect."
            )
        
        access_token = github_account["access_token"]
        username = github_account["platform_username"]
        
        # Check if this is first fetch or refresh
        last_fetch_info = await github_data_service.get_last_fetch_info(user_id)
        fetch_type = "initial" if not last_fetch_info else "refresh"
        
        # Get last commit date for incremental fetch
        since_date = None
        if fetch_type == "refresh":
            since_date = await github_data_service.get_last_commit_date(user_id)
            print(f"📅 Last commit date: {since_date}")
        
        # Fetch commits from GitHub
        print(f"🔄 Fetching commits from GitHub (last {days} days)...")
        result = await github_oauth.batch_fetch_commits(
            access_token=access_token,
            username=username,
            since_date=since_date,
            days=days,
            max_repos=20
        )
        
        commits = result["commits"]
        print(f"✅ Fetched {len(commits)} commits from {result['repositories_checked']} repositories")
        
        # Save commits to database
        if commits:
            print(f"💾 Saving commits to database...")
            save_result = await github_data_service.save_github_commits(user_id, commits)
            
            new_commits = save_result["new_commits"]
            skipped = save_result["skipped"]
            
            print(f"✅ Saved {new_commits} new commits (skipped {skipped} duplicates)")
            
            # Update fetch log
            from datetime import datetime
            last_commit_date = None
            if commits:
                last_commit_date_str = commits[0]["commit"]["author"]["date"]
                last_commit_date = datetime.fromisoformat(last_commit_date_str.replace("Z", "+00:00"))
            
            await github_data_service.update_fetch_log(
                user_id=user_id,
                last_commit_date=last_commit_date,
                total_count=new_commits,
                fetch_type=fetch_type
            )
            
            # Auto-update context only on first fetch (to save API costs)
            if fetch_type == "initial":
                print(f"🤖 First fetch detected - Generating initial context...")
                try:
                    # Check if context already exists
                    context_exists = await context_service.context_exists(user_id)
                    if not context_exists:
                        await context_service.update_user_context(user_id, use_ai=True)
                        print(f"✅ Initial context generated successfully")
                except Exception as e:
                    print(f"⚠️ Warning: Failed to generate context: {str(e)}")
                    # Don't fail the whole request if context generation fails
            
            # Auto-generate embeddings for new commits (Phase 3)
            embedding_result = None
            if new_commits > 0:
                print(f"\n🔢 Auto-generating embeddings for {new_commits} new commits...")
                try:
                    embedding_job_service = get_embedding_job_service()
                    embedding_result = await embedding_job_service.generate_embedding_for_new_commits(
                        user_id,
                        batch_size=50
                    )
                    print(f"✅ Generated {embedding_result['embeddings_generated']} embeddings")
                except Exception as e:
                    print(f"⚠️ Warning: Failed to generate embeddings: {str(e)}")
                    # Don't fail the whole request if embedding generation fails
            
            return {
                "success": True,
                "message": f"Fetched {new_commits} new commits from {result['repositories_checked']} repositories",
                "data": {
                    "new_commits": new_commits,
                    "skipped_duplicates": skipped,
                    "repositories_checked": result['repositories_checked'],
                    "fetch_type": fetch_type,
                    "embeddings_generated": embedding_result["embeddings_generated"] if embedding_result else 0
                }
            }
        else:
            return {
                "success": True,
                "message": "No new commits found",
                "data": {
                    "new_commits": 0,
                    "skipped_duplicates": 0,
                    "repositories_checked": result['repositories_checked'],
                    "fetch_type": fetch_type
                }
            }
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error fetching GitHub data: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/github/activity")
async def get_github_activity(
    authorization: Optional[str] = Header(None),
    limit: int = 100,
    days: Optional[int] = None
):
    """
    Get user's stored GitHub activity.
    
    Args:
        authorization: JWT token in Authorization header
        limit: Maximum number of commits to return (default: 100)
        days: Only return commits from last N days (optional)
        
    Returns:
        List of commits from database
    """
    try:
        # Verify user is authenticated
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        token = authorization.split(" ")[1]
        user_data = supabase_service.verify_jwt_token(token)
        user_id = user_data.get("sub")
        
        # Get activity from database
        activity = await github_data_service.get_user_github_activity(
            user_id=user_id,
            limit=limit,
            days=days
        )
        
        # Get additional stats
        total_commits = await github_data_service.get_commit_count(user_id)
        repositories = await github_data_service.get_repositories(user_id)
        last_fetch_info = await github_data_service.get_last_fetch_info(user_id)
        
        return {
            "success": True,
            "data": {
                "commits": activity,
                "total_commits": total_commits,
                "repositories": repositories,
                "last_fetch": last_fetch_info
            }
        }
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error getting GitHub activity: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/github/status")
async def get_github_status(authorization: Optional[str] = Header(None)):
    """
    Get GitHub data freshness status with smart refresh recommendations.
    
    Args:
        authorization: JWT token in Authorization header
        
    Returns:
        Status information about GitHub data with refresh recommendations
    """
    try:
        # Verify user is authenticated
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        token = authorization.split(" ")[1]
        user_data = supabase_service.verify_jwt_token(token)
        user_id = user_data.get("sub")
        
        # Get comprehensive refresh recommendation
        recommendation = await github_data_service.get_refresh_recommendation(user_id)
        
        # Get repositories list
        repositories = await github_data_service.get_repositories(user_id)
        
        return {
            "success": True,
            "data": {
                "total_commits": recommendation["total_commits_stored"],
                "last_fetch_time": recommendation["last_fetch_time"],
                "last_commit_date": recommendation["last_commit_date"],
                "needs_refresh": recommendation["should_refresh"],
                "hours_since_fetch": recommendation["hours_since_fetch"],
                "refresh_reason": recommendation["reason"],
                "has_data": recommendation["has_data"],
                "repositories_count": len(repositories),
                "repositories": repositories
            }
        }
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error getting GitHub status: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/github/refresh-check")
async def check_refresh_needed(
    authorization: Optional[str] = Header(None),
    hours_threshold: int = 24
):
    """
    Check if GitHub data needs refresh based on custom threshold.
    
    Args:
        authorization: JWT token in Authorization header
        hours_threshold: Hours after which data is considered stale (default: 24)
        
    Returns:
        Simple refresh check result
    """
    try:
        # Verify user is authenticated
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        token = authorization.split(" ")[1]
        user_data = supabase_service.verify_jwt_token(token)
        user_id = user_data.get("sub")
        
        # Check if refresh is needed
        refresh_check = await github_data_service.should_refresh_data(user_id, hours_threshold)
        
        return {
            "success": True,
            "data": refresh_check
        }
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error checking refresh status: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/github/context")
async def get_github_context(authorization: Optional[str] = Header(None)):
    """
    Get user's GitHub context summary (cached).
    
    Args:
        authorization: JWT token in Authorization header
        
    Returns:
        User context with projects, tech stack, and activity summary
    """
    try:
        # Verify user is authenticated
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        token = authorization.split(" ")[1]
        user_data = supabase_service.verify_jwt_token(token)
        user_id = user_data.get("sub")
        
        print(f"\n📊 User {user_id} - Getting GitHub context...")
        
        # Get cached context
        context = await context_service.get_user_context(user_id)
        
        if not context:
            return {
                "success": True,
                "data": None,
                "message": "No context available. Please fetch GitHub data first."
            }
        
        return {
            "success": True,
            "data": context
        }
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error getting GitHub context: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/github/analyze")
async def analyze_github_data(authorization: Optional[str] = Header(None)):
    """
    Analyze GitHub data and generate AI insights (manual refresh).
    This endpoint costs API tokens as it calls Gemini.
    
    Args:
        authorization: JWT token in Authorization header
        
    Returns:
        Updated context with fresh AI insights
    """
    try:
        # Verify user is authenticated
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        token = authorization.split(" ")[1]
        user_data = supabase_service.verify_jwt_token(token)
        user_id = user_data.get("sub")
        
        print(f"\n🤖 User {user_id} - Analyzing GitHub data with AI...")
        
        # Check if user has any GitHub data
        github_account = supabase_service.get_platform_connection(user_id, "github")
        
        if not github_account:
            raise HTTPException(
                status_code=400,
                detail="No GitHub account connected. Please connect your account first."
            )
        
        # Refresh AI insights
        context = await context_service.refresh_ai_insights(user_id)
        
        return {
            "success": True,
            "data": context,
            "message": "AI insights generated successfully"
        }
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error analyzing GitHub data: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# EMBEDDINGS ENDPOINTS (Phase 3 - Semantic Search)
# ============================================================================

@app.post("/api/embeddings/generate")
async def generate_embedding(
    request: dict,
    authorization: Optional[str] = Header(None)
):
    """
    Generate embedding for a single text.
    
    Test endpoint to verify embedding service works.
    
    Request body:
        {
            "text": "Your text here",
            "task_type": "RETRIEVAL_DOCUMENT" (optional)
        }
    
    Returns:
        {
            "success": true,
            "embedding": [...],
            "dimension": 768,
            "text_length": 25
        }
    """
    try:
        # Verify user is authenticated
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        token = authorization.split(" ")[1]
        user_data = supabase_service.verify_jwt_token(token)
        user_id = user_data.get("sub")
        
        # Get text from request
        text = request.get("text")
        if not text:
            raise HTTPException(status_code=400, detail="Text is required")
        
        task_type = request.get("task_type", "RETRIEVAL_DOCUMENT")
        
        print(f"\n🔢 User {user_id} - Generating embedding for text: {text[:50]}...")
        
        # Generate embedding
        embedding_service = get_embedding_service()
        embedding = embedding_service.generate_embedding(text, task_type=task_type)
        
        return {
            "success": True,
            "embedding": embedding,
            "dimension": len(embedding),
            "text_length": len(text),
            "task_type": task_type,
            "model": embedding_service.model
        }
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error generating embedding: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/embeddings/batch")
async def generate_embeddings_batch(
    request: dict,
    authorization: Optional[str] = Header(None)
):
    """
    Generate embeddings for multiple texts in one API call (efficient).
    
    Request body:
        {
            "texts": ["Text 1", "Text 2", "Text 3"],
            "task_type": "RETRIEVAL_DOCUMENT" (optional)
        }
    
    Returns:
        {
            "success": true,
            "embeddings": [[...], [...], [...]],
            "count": 3,
            "dimension": 768
        }
    """
    try:
        # Verify user is authenticated
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        token = authorization.split(" ")[1]
        user_data = supabase_service.verify_jwt_token(token)
        user_id = user_data.get("sub")
        
        # Get texts from request
        texts = request.get("texts")
        if not texts or not isinstance(texts, list):
            raise HTTPException(status_code=400, detail="Texts array is required")
        
        task_type = request.get("task_type", "RETRIEVAL_DOCUMENT")
        
        print(f"\n🔢 User {user_id} - Generating {len(texts)} embeddings in batch...")
        
        # Generate embeddings
        embedding_service = get_embedding_service()
        embeddings = embedding_service.generate_embeddings_batch(texts, task_type=task_type)
        
        return {
            "success": True,
            "embeddings": embeddings,
            "count": len(embeddings),
            "dimension": len(embeddings[0]) if embeddings else 0,
            "task_type": task_type,
            "model": embedding_service.model
        }
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error generating batch embeddings: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/embeddings/similarity")
async def calculate_similarity(
    request: dict,
    authorization: Optional[str] = Header(None)
):
    """
    Calculate similarity between two texts.
    
    Request body:
        {
            "text1": "First text",
            "text2": "Second text"
        }
    
    Returns:
        {
            "success": true,
            "similarity": 0.87,
            "text1": "First text",
            "text2": "Second text"
        }
    """
    try:
        # Verify user is authenticated
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        token = authorization.split(" ")[1]
        user_data = supabase_service.verify_jwt_token(token)
        user_id = user_data.get("sub")
        
        # Get texts from request
        text1 = request.get("text1")
        text2 = request.get("text2")
        
        if not text1 or not text2:
            raise HTTPException(status_code=400, detail="Both text1 and text2 are required")
        
        print(f"\n🔍 User {user_id} - Calculating similarity...")
        
        # Generate embeddings
        embedding_service = get_embedding_service()
        emb1 = embedding_service.generate_embedding(text1, task_type="SEMANTIC_SIMILARITY")
        emb2 = embedding_service.generate_embedding(text2, task_type="SEMANTIC_SIMILARITY")
        
        # Calculate similarity
        similarity = embedding_service.calculate_similarity(emb1, emb2)
        
        return {
            "success": True,
            "similarity": round(similarity, 4),
            "text1": text1,
            "text2": text2,
            "interpretation": (
                "Identical" if similarity > 0.95 else
                "Very similar" if similarity > 0.8 else
                "Somewhat similar" if similarity > 0.6 else
                "Slightly similar" if similarity > 0.4 else
                "Not similar"
            )
        }
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error calculating similarity: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/embeddings/info")
async def get_embedding_info(authorization: Optional[str] = Header(None)):
    """
    Get information about the embedding model.
    
    Returns model details, dimensions, and capabilities.
    """
    try:
        # Verify user is authenticated
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        token = authorization.split(" ")[1]
        supabase_service.verify_jwt_token(token)
        
        # Get model info
        embedding_service = get_embedding_service()
        info = embedding_service.get_model_info()
        
        return {
            "success": True,
            "data": info
        }
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error getting embedding info: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# GITHUB EMBEDDINGS ENDPOINTS (Phase 3 Day 2 - Semantic Search)
# ============================================================================

@app.post("/api/github/embeddings/generate")
async def generate_github_embeddings(
    request: dict,
    authorization: Optional[str] = Header(None)
):
    """
    Generate embeddings for GitHub commits.
    
    Processes commits that don't have embeddings yet and stores them in the database.
    Uses batch processing for efficiency.
    
    Request body:
        {
            "batch_size": 50 (optional, default: 50)
        }
    
    Returns:
        {
            "success": true,
            "embeddings_generated": 45,
            "failed": 0,
            "stats": {...}
        }
    """
    try:
        # Verify user is authenticated
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        token = authorization.split(" ")[1]
        user_data = supabase_service.verify_jwt_token(token)
        user_id = user_data.get("sub")
        
        batch_size = request.get("batch_size", 50)
        
        print(f"\n🔢 User {user_id} - Generating embeddings for GitHub commits...")
        
        # Get commits without embeddings
        commits = await github_data_service.get_commits_without_embeddings(user_id, limit=batch_size)
        
        if not commits:
            return {
                "success": True,
                "message": "All commits already have embeddings",
                "embeddings_generated": 0,
                "stats": await github_data_service.get_embedding_stats(user_id)
            }
        
        print(f"   Found {len(commits)} commits without embeddings")
        
        # Extract commit messages for batch embedding
        commit_messages = [commit["commit_message"] for commit in commits]
        
        # Generate embeddings in batch
        embedding_service = get_embedding_service()
        embeddings = embedding_service.generate_embeddings_batch(
            commit_messages,
            task_type="RETRIEVAL_DOCUMENT"
        )
        
        print(f"   Generated {len(embeddings)} embeddings")
        
        # Prepare batch data for saving
        commit_embeddings = []
        for i, commit in enumerate(commits):
            if i < len(embeddings):
                commit_embeddings.append({
                    "commit_hash": commit["commit_hash"],
                    "embedding": embeddings[i]
                })
        
        # Save embeddings to database
        result = await github_data_service.save_commit_embeddings_batch(
            user_id,
            commit_embeddings
        )
        
        print(f"   Saved {result['success']} embeddings, {result['failed']} failed")
        
        # Get updated stats
        stats = await github_data_service.get_embedding_stats(user_id)
        
        return {
            "success": True,
            "embeddings_generated": result["success"],
            "failed": result["failed"],
            "processed_commits": len(commits),
            "stats": stats
        }
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error generating GitHub embeddings: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/github/embeddings/search")
async def search_github_commits(
    request: dict,
    authorization: Optional[str] = Header(None)
):
    """
    Search for similar GitHub commits using semantic search.
    
    Request body:
        {
            "query": "machine learning projects",
            "limit": 10 (optional, default: 10),
            "min_similarity": 0.5 (optional, default: 0.5)
        }
    
    Returns:
        {
            "success": true,
            "query": "machine learning projects",
            "results": [
                {
                    "commit_hash": "abc123",
                    "commit_message": "Added ML model",
                    "similarity": 0.87,
                    ...
                }
            ],
            "count": 5
        }
    """
    try:
        # Verify user is authenticated
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        token = authorization.split(" ")[1]
        user_data = supabase_service.verify_jwt_token(token)
        user_id = user_data.get("sub")
        
        # Get query parameters
        query = request.get("query")
        if not query:
            raise HTTPException(status_code=400, detail="Query is required")
        
        limit = request.get("limit", 10)
        min_similarity = request.get("min_similarity", 0.5)
        
        print(f"\n🔍 User {user_id} - Searching commits for: '{query}'")
        
        # Generate query embedding
        embedding_service = get_embedding_service()
        query_embedding = embedding_service.generate_query_embedding(query)
        
        # Search for similar commits
        results = await github_data_service.search_similar_commits(
            user_id,
            query_embedding,
            limit=limit,
            min_similarity=min_similarity
        )
        
        print(f"   Found {len(results)} similar commits")
        
        return {
            "success": True,
            "query": query,
            "results": results,
            "count": len(results),
            "min_similarity": min_similarity
        }
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error searching GitHub commits: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/github/embeddings/stats")
async def get_github_embedding_stats(authorization: Optional[str] = Header(None)):
    """
    Get statistics about GitHub commit embeddings.
    
    Returns:
        {
            "success": true,
            "stats": {
                "total_commits": 150,
                "commits_with_embeddings": 100,
                "commits_without_embeddings": 50,
                "percentage_complete": 66.67,
                "ready_for_search": true
            }
        }
    """
    try:
        # Verify user is authenticated
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        token = authorization.split(" ")[1]
        user_data = supabase_service.verify_jwt_token(token)
        user_id = user_data.get("sub")
        
        # Get embedding stats
        stats = await github_data_service.get_embedding_stats(user_id)
        
        return {
            "success": True,
            "stats": stats
        }
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error getting embedding stats: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# EMBEDDING JOB ENDPOINTS (Phase 3 Day 3 - Batch Processing)
# ============================================================================

@app.post("/api/github/embeddings/generate-all")
async def generate_all_embeddings(
    request: dict,
    authorization: Optional[str] = Header(None)
):
    """
    Generate embeddings for ALL commits that don't have them (batch job).
    
    This processes all commits in batches of 50 for efficiency.
    Use this for initial embedding generation or to catch up on missing embeddings.
    
    Request body:
        {
            "batch_size": 50 (optional),
            "max_commits": 500 (optional, limit total commits to process)
        }
    
    Returns:
        {
            "success": true,
            "total_processed": 200,
            "embeddings_generated": 195,
            "failed": 5,
            "batches_processed": 4,
            "stats": {...}
        }
    """
    try:
        # Verify user is authenticated
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        token = authorization.split(" ")[1]
        user_data = supabase_service.verify_jwt_token(token)
        user_id = user_data.get("sub")
        
        batch_size = request.get("batch_size", 50)
        max_commits = request.get("max_commits")
        
        print(f"\n🚀 User {user_id} - Starting batch embedding generation...")
        
        # Run the embedding job
        embedding_job_service = get_embedding_job_service()
        result = await embedding_job_service.generate_embeddings_for_user(
            user_id,
            batch_size=batch_size,
            max_commits=max_commits
        )
        
        return {
            "success": True,
            **result
        }
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error in batch embedding generation: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/github/embeddings/status")
async def get_embedding_job_status(authorization: Optional[str] = Header(None)):
    """
    Get detailed status of embedding generation progress.
    
    Returns:
        {
            "success": true,
            "status": {
                "total_commits": 200,
                "commits_with_embeddings": 150,
                "commits_needing_embeddings": 50,
                "percentage_complete": 75.0,
                "ready_for_search": true,
                "estimated_batches_remaining": 1,
                "estimated_api_calls": 1,
                "status_message": "Almost done! 50 commits remaining"
            }
        }
    """
    try:
        # Verify user is authenticated
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        token = authorization.split(" ")[1]
        user_data = supabase_service.verify_jwt_token(token)
        user_id = user_data.get("sub")
        
        # Get detailed status
        embedding_job_service = get_embedding_job_service()
        status = await embedding_job_service.get_embedding_status(user_id)
        
        return {
            "success": True,
            "status": status
        }
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error getting embedding status: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# SUBSCRIPTION & PAYMENT ENDPOINTS
# ============================================================================

@app.get("/api/subscription/status")
async def get_subscription_status(authorization: Optional[str] = Header(None)):
    """
    Get user's subscription status.
    
    Returns:
        Subscription details: plan_type, posts_used, posts_limit, remaining
    """
    try:
        # Verify user is authenticated
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        token = authorization.split(" ")[1]
        user_data = supabase_service.verify_jwt_token(token)
        user_id = user_data.get("sub")
        
        subscription_service = get_subscription_service()
        status = subscription_service.get_subscription_status(user_id)
        
        return {
            "success": True,
            "subscription": status
        }
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error getting subscription status: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/payments/create-order")
async def create_payment_order(authorization: Optional[str] = Header(None)):
    """
    Create Razorpay order for Pro subscription.
    
    Returns:
        Order details: order_id, amount, key_id for frontend checkout
    """
    try:
        # Verify user is authenticated
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        token = authorization.split(" ")[1]
        user_data = supabase_service.verify_jwt_token(token)
        user_id = user_data.get("sub")
        
        print(f"\n💳 User {user_id} - Creating payment order for Pro subscription...")
        
        # Create Razorpay order ($5 = 500 cents)
        razorpay_service = get_razorpay_service()
        order = razorpay_service.create_order(amount=5, currency="USD", user_id=user_id)
        
        print(f"✅ Created Razorpay order: {order.get('id')}")
        
        return {
            "success": True,
            "order": {
                "id": order.get("id"),
                "amount": order.get("amount"),  # Amount in smallest unit (cents for USD, paise for INR)
                "currency": order.get("currency"),
                "key_id": razorpay_service.key_id  # For frontend checkout
            }
        }
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error creating payment order: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/payments/verify")
async def verify_payment(
    request: dict,
    authorization: Optional[str] = Header(None)
):
    """
    Verify Razorpay payment and activate Pro subscription.
    
    Request body:
        {
            "razorpay_order_id": "...",
            "razorpay_payment_id": "...",
            "razorpay_signature": "..."
        }
    
    Returns:
        Success message and updated subscription
    """
    try:
        # Verify user is authenticated
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        token = authorization.split(" ")[1]
        user_data = supabase_service.verify_jwt_token(token)
        user_id = user_data.get("sub")
        
        # Get payment details from request
        razorpay_order_id = request.get("razorpay_order_id")
        razorpay_payment_id = request.get("razorpay_payment_id")
        razorpay_signature = request.get("razorpay_signature")
        
        if not all([razorpay_order_id, razorpay_payment_id, razorpay_signature]):
            raise HTTPException(status_code=400, detail="Missing payment details")
        
        print(f"\n🔐 User {user_id} - Verifying payment...")
        
        # Verify payment signature
        razorpay_service = get_razorpay_service()
        is_verified = razorpay_service.verify_payment(
            razorpay_order_id,
            razorpay_payment_id,
            razorpay_signature
        )
        
        if not is_verified:
            raise HTTPException(status_code=400, detail="Payment verification failed")
        
        print(f"✅ Payment verified successfully")
        
        # Upgrade user to Pro
        subscription_service = get_subscription_service()
        success = subscription_service.upgrade_to_pro(
            user_id,
            razorpay_payment_id,
            razorpay_order_id
        )
        
        if not success:
            raise HTTPException(status_code=500, detail="Failed to upgrade subscription")
        
        print(f"✅ User {user_id} upgraded to Pro")
        
        # Get updated subscription status
        status = subscription_service.get_subscription_status(user_id)
        
        return {
            "success": True,
            "message": "Payment verified and Pro subscription activated!",
            "subscription": status
        }
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error verifying payment: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)


