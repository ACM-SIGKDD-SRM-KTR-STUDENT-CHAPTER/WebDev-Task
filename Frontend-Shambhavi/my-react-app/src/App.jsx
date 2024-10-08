import React from 'react'
import Sidebar from './Components/Sidebar'
import Header from './Components/Header'
import Tabs from './Components/Tabs'
import StudentData from './Components/StudentData'
import Charts from './Components/Charts'
import CareerOptions from './Components/CareerOptions'
import './App.css'
import 'primeicons/primeicons.css';

const App = () => {
  return (
    <div className="app">
        <Sidebar/>
    <main className="main-content">
        <Header/>
        <Tabs/>
        <StudentData/>
        <Charts/>
        <CareerOptions/>

    </main>
    </div>
  )
}

export default App