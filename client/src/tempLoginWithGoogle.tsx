import axios from 'axios';

function App() {
  const handleSignin = async () => {
    const res = await axios.get('http://localhost:3000/api/v1/user/auth/google');

    console.log(res);

    const requestURL = res.data.url;

    window.location.href = requestURL;


  }

  return (
    <div className="py-4">
      <h1 className="text-center">Signin with google</h1>
      <button onClick={() => handleSignin()} className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded"> Signin With google</button>
    </div>
  )
}

export default App
