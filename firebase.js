import { initializeApp } from "firebase/app";
import { getAuth, GoogleAuthProvider, signInWithPopup } from "firebase/auth";

// Your web app's Firebase configuration
const firebaseConfig = {
  apiKey: "AIzaSyBXwSuHOUtnQxnhIXDb1x7r55V0NXiUIrs",
  authDomain: "ss-login-5cfe3.firebaseapp.com",
  projectId: "ss-login-5cfe3",
  storageBucket: "ss-login-5cfe3.appspot.com",
  messagingSenderId: "774216790441",
  appId: "1:774216790441:web:a84ab1414c819f7e8554b8"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);

// Initialize and export Firebase services
export const auth = getAuth(app);
const googleProvider = new GoogleAuthProvider();

// Function to trigger the Google Sign-In popup
export const signInWithGoogle = () => {
  return signInWithPopup(auth, googleProvider);
};