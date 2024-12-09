import Navbar from "../components/Navbar"

const pollCount = 1379;

const Home = () => {
  return (
    // container
    <div className="flex flex-col bg-background-landscape bg-cover bg-center h-[100vh] p-12">

      <Navbar />

      <div className="flex flex-col items-center">
        {/* header */}
        <header>
          <div className="flex flex-col mt-[150px]">
            <h1 className="text-[40px] text-center font-bold tracking-tight">Know what the world thinks</h1>
            <p className="mt-4 text-base text-[#5C5B61] text-center">
              Create polls, gather opinions
            </p>
          </div>
        </header>

        {/* cta */}
        <section>
          <div className="flex mt-[56px] justify-between">
            <button className="bg-primary px-16 py-5 font-bold rounded-[20px] mr-[100px] hover:translate-y-[-2px] transition-all">
              Create a poll
            </button>
            <button className="bg-base-400 px-16 py-5 rounded-[20px] hover:translate-y-[-2px] transition-all">
              Browse polls
            </button>
          </div>
        </section>

        <p className="mt-[72px] text-2xl font-bold">
          <span className="inline-block w-fit border-b-4 border-dashed border-primary"> {pollCount} </span> polls created so far
        </p>

      </div>
    </div>
  )
}

export default Home;